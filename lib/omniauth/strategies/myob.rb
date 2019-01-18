require "omniauth/strategies/oauth2"

module OmniAuth
  module Strategies
    class Myob < OmniAuth::Strategies::OAuth2
      option :name, "myob"

      option :client_options, {
        site: "https://secure.myob.com",
        authorize_url: "/oauth2/account/authorize",
        token_url: "/oauth2/v1/authorize",
      }

      option :authorize_params, {
        "scope" => "la.global",
      }

      extra do
        {raw_info: raw_info["items"]}
      end

      def raw_info
        @raw_info ||= access_token.get('https://api.myob.com/au/essentials/businesses',
          { headers: headers }
        ).parsed
      end

      private

      def headers
        @headers ||= {
          "Accept" => "application/json",
          "x-myobapi-key" => options.client_id,
          "x-myobapi-version" => "v0",
        }
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end
    end
  end
end
