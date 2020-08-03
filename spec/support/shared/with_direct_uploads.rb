#-- encoding: UTF-8

#-- copyright
# OpenProject is an open source project management software.
# Copyright (C) 2012-2020 the OpenProject GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version 3.
#
# OpenProject is a fork of ChiliProject, which is a fork of Redmine. The copyright follows:
# Copyright (C) 2006-2017 Jean-Philippe Lang
# Copyright (C) 2010-2013 the ChiliProject Team
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# See docs/COPYRIGHT.rdoc for more details.
#++

class FogAttachment < Attachment
  # Remounting the uploader overrides the original file setter taking care of setting,
  # among other things, the content type. So we have to restore that original
  # method this way.
  # We do this in a new, separate class, as to not interfere with any other specs.
  alias_method :set_file, :file=
  mount_uploader :file, FogFileUploader
  alias_method :file=, :set_file
end

RSpec.configure do |config|
  config.before(:each) do |example|
    next unless example.metadata[:with_direct_uploads]

    allow(Attachment).to receive(:create) do |*args|
      # We don't use create here because this would cause an infinite loop as FogAttachment's #create
      # uses the base class's #create which is what we are mocking here. All this is necessary to begin
      # with because the Attachment class is initialized with the LocalFileUploader before this test
      # is ever run and we need remote attachments using the FogFileUploader in this scenario.
      record = FogAttachment.new *args
      record.save
      record
    end

    Fog.mock!

    connection = Fog::Storage.new provider: "AWS"
    connection.directories.create key: "my-bucket"

    CarrierWave::Configuration.configure_fog!

    proxy.stub("https://" + OpenProject::Configuration.remote_storage_host + ":443/", method: 'options').and_return(
      headers: {
        'Access-Control-Allow-Methods' => 'POST',
        'Access-Control-Allow-Origin'  => '*'
      },
      code: 200
    )

    if example.metadata[:with_direct_uploads] == :redirect
      proxy
        .stub("https://" + OpenProject::Configuration.remote_storage_host + ":443/", method: 'post')
        .and_return(Proc.new { |params, headers, body, url, method|
          key = body.scan(/key"\s*([^\s]+)\s/m).flatten.first
          redirect_url = body.scan(/success_action_redirect"\s*(http[^\s]+)\s/m).flatten.first
          ok = body =~ /X-Amz-Signature/ # check that the expected post to AWS was made with the form fields

          {
            code: ok ? 302 : 403,
            headers: {
              'Location' => ok ? redirect_url + '?key=' + CGI.escape(key) : nil,
              'Access-Control-Allow-Methods' => 'POST',
              'Access-Control-Allow-Origin'  => '*'
            }
          }
        })
    else # use status response instead of redirect by default
      proxy
        .stub("https://" + OpenProject::Configuration.remote_storage_host + ":443/", method: 'post')
        .and_return(Proc.new { |params, headers, body, url, method|
          {
            code: (body =~ /X-Amz-Signature/) ? 201 : 403, # check that the expected post to AWS was made with the form fields
            headers: {
              'Access-Control-Allow-Methods' => 'POST',
              'Access-Control-Allow-Origin'  => '*'
            }
          }
        })
    end
  end

  config.around(:each) do |example|
    enabled = example.metadata[:with_direct_uploads]

    unless enabled
      example.run
      next
    end

    example.metadata[:with_config] = Hash(example.metadata[:with_config]).merge(
      attachments_storage: :fog,
      fog: {
        directory: 'my-bucket',
        credentials: {
          provider: 'AWS',
          aws_access_key_id: 'someaccesskeyid',
          aws_secret_access_key: 'someprivateaccesskey',
          region: 'us-east-1'
        }
      }
    )

    example.metadata[:driver] = :headless_firefox_billy

    csp_config = SecureHeaders::Configuration.instance_variable_get("@default_config").csp
    csp_config.connect_src = ["'self'", "my-bucket.s3.amazonaws.com"]

    begin
      example.run
    ensure
      csp_config.connect_src = %w('self')
    end
  end
end
