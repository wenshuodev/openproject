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

class WithDirectUploads
  attr_reader :context

  def initialize(context)
    @context = context
  end

  ##
  # We need this so calls to rspec mocks (allow, expect etc.) will work here as expected.
  def method_missing(method, *args, &block)
    if context.respond_to?(method)
      context.send method, *args, &block
    else
      super
    end
  end

  def before(example)
    stub_config example

    mock_fog
    stub_frontend redirect: example.metadata[:with_direct_uploads] == :redirect if example.metadata[:js]
  end

  def around(example)
    example.metadata[:driver] = :headless_firefox_billy

    csp_config = SecureHeaders::Configuration.instance_variable_get("@default_config").csp
    csp_config.connect_src = ["'self'", "my-bucket.s3.amazonaws.com"]

    begin
      example.run
    ensure
      csp_config.connect_src = %w('self')
    end
  end

  def mock_fog
    allow(Attachment).to receive(:create) do |*args|
      # We don't use create here because this would cause an infinite loop as FogAttachment's #create
      # uses the base class's #create which is what we are mocking here. All this is necessary to begin
      # with because the Attachment class is initialized with the LocalFileUploader before this test
      # is ever run and we need remote attachments using the FogFileUploader in this scenario.
      record = FogAttachment.new *args
      record.save
      record
    end
  end

  def stub_frontend(redirect: false)
    proxy.stub("https://" + OpenProject::Configuration.remote_storage_host + ":443/", method: 'options').and_return(
      headers: {
        'Access-Control-Allow-Methods' => 'POST',
        'Access-Control-Allow-Origin'  => '*'
      },
      code: 200
    )

    if redirect
      stub_with_redirect
    else # use status response instead of redirect by default
      stub_with_status
    end
  end

  def stub_with_redirect
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
  end

  def stub_with_status
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

  # def stub_direct_uploader
  #   creds = config[:fog][:credentials]

  #   allow_any_instance_of(DirectFogUploader).to receive(:aws_access_key_id).and_return creds[:aws_access_key_id]
  #   allow_any_instance_of(DirectFogUploader).to receive(:aws_secret_access_key).and_return creds[:aws_secret_access_key]
  #   allow_any_instance_of(DirectFogUploader).to receive(:provider).and_return creds[:provider]
  #   allow_any_instance_of(DirectFogUploader).to receive(:region).and_return creds[:region]
  #   allow_any_instance_of(DirectFogUploader).to receive(:directory).and_return config[:fog][:directory]
  # end

  def stub_config(example)
    WithConfig.new(context).before example, config
  end

  def config
    {
      attachments_storage: :fog,
      fog: {
        directory: MockCarrierwave.bucket,
        credentials: MockCarrierwave.credentials
      }
    }
  end
end

RSpec.configure do |config|
  config.before(:each) do |example|
    next unless example.metadata[:with_direct_uploads]

    WithDirectUploads.new(self).before example
  end

  config.around(:each) do |example|
    enabled = example.metadata[:with_direct_uploads]

    unless enabled
      example.run
      next
    end

    WithDirectUploads.new(self).around example
  end
end
