class Auth::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  def google
    raise request.env['omniauth.auth'].to_yaml
  end
end
