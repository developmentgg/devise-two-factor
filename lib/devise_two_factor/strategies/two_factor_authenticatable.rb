module Devise
  module Strategies
    class TwoFactorAuthenticatable < Devise::Strategies::DatabaseAuthenticatable

      def authenticate!
        resource = mapping.to.find_for_database_authentication(authentication_hash)

        # ignores otp when requesting pre_authenticate
        resource&.otp_required_for_login = false if path_is?('/pre_authenticate')

        # forces otp when requesting activating otp for the first time
        resource&.otp_required_for_login = true if path_is?('/activate_otp_and_sign_in')

        # We authenticate in two cases:
        # 1. The password and the OTP are correct
        # 2. The password is correct, and OTP is not required for login
        # We check the OTP, then defer to DatabaseAuthenticatable
        if validate(resource) { validate_otp(resource) }
          super
        end

        fail(Devise.paranoid ? :invalid : :not_found_in_database) unless resource

        # We want to cascade to the next strategy if this one fails,
        # but database authenticatable automatically halts on a bad password
        @halted = false if @result == :failure

        # saves the resource if login was successfull
        resource&.save if path_is?('/activate_otp_and_sign_in') && @result != :failure
      end

      def validate_otp(resource)
        resource&.otp_required_for_login = true if path_is?('') && resource.force_otp?

        return true unless resource.otp_required_for_login
        return if params[scope]['otp_attempt'].nil?
        resource.validate_and_consume_otp!(params[scope]['otp_attempt'])
      end

      def path_is?(path)
        request.path == "/users/session#{path}"
      end
    end
  end
end

Warden::Strategies.add(:two_factor_authenticatable, Devise::Strategies::TwoFactorAuthenticatable)
