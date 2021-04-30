require 'omniauth-oauth2'
require 'json'
require 'net/http'

module OmniAuth
  module Strategies
    class Line < OmniAuth::Strategies::OAuth2
      option :name, 'line'
      option :scope, 'profile openid'

      option :token_params, {
        grant_type: 'authorization_code'
      }

      option :client_options, {
        site: 'https://access.line.me',
        authorize_url: '/oauth2/v2.1/authorize',
        token_url: '/oauth2/v2.1/token'
      }

      # host changed
      def callback_phase
        options[:client_options][:site] = 'https://api.line.me'
        super
      end

      uid { raw_info['userId'] }

      info do
        {
          name:        raw_info['displayName'],
          image:       raw_info['pictureUrl'],
          description: raw_info['statusMessage'],
          email:       raw_info["email"]
        }
      end

      def email
        params = {
          id_token: @id_token,
          client_id: client.id
        }
        response = Net::HTTP.post_form(URI("https://api.line.me/oauth2/v2.1/verify"), params)
        JSON.load(response.body)["email"]
      end

      # Require: Access token with PROFILE permission issued.
      def raw_info
        return @raw_info if @raw_info.present?
        @raw_info = JSON.load(access_token.get('v2/profile').body)
        @raw_info["email"] = email
        @raw_info
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

      def build_access_token
        verifier = request.params["code"]
        get_token_params = {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true))
        result = client.auth_code.get_token(verifier, get_token_params, deep_symbolize(options.auth_token_params))
        @id_token = result.params["id_token"]
        return result
      end

      def callback_url
        full_host + script_name + callback_path
      end

    end
  end
end
