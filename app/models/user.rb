# frozen_string_literal: true
# == Schema Information
#
# Table name: users
#
#  id                        :integer          not null, primary key
#  email                     :string           default(""), not null
#  account_id                :integer          not null
#  created_at                :datetime         not null
#  updated_at                :datetime         not null
#  encrypted_password        :string           default(""), not null
#  reset_password_token      :string
#  reset_password_sent_at    :datetime
#  remember_created_at       :datetime
#  sign_in_count             :integer          default(0), not null
#  current_sign_in_at        :datetime
#  last_sign_in_at           :datetime
#  current_sign_in_ip        :inet
#  last_sign_in_ip           :inet
#  admin                     :boolean          default(FALSE)
#  confirmation_token        :string
#  confirmed_at              :datetime
#  confirmation_sent_at      :datetime
#  unconfirmed_email         :string
#  locale                    :string
#  encrypted_otp_secret      :string
#  encrypted_otp_secret_iv   :string
#  encrypted_otp_secret_salt :string
#  consumed_timestep         :integer
#  otp_required_for_login    :boolean
#  last_emailed_at           :datetime
#  otp_backup_codes          :string           is an Array
#  allowed_languages         :string           default([]), not null, is an Array
#

class User < ApplicationRecord
  include Settings::Extend

  devise :omniauthable, :registerable, :recoverable,
         :rememberable, :trackable, :validatable, :confirmable,
         :two_factor_authenticatable, :two_factor_backupable,
         omniauth_providers: %i(google),
         otp_secret_encryption_key: ENV['OTP_SECRET'],
         otp_number_of_backup_codes: 10

  belongs_to :account, inverse_of: :user, required: true
  accepts_nested_attributes_for :account

  validates :locale, inclusion: I18n.available_locales.map(&:to_s), unless: 'locale.nil?'
  validates :email, email: true

  scope :recent,    -> { order('id desc') }
  scope :admins,    -> { where(admin: true) }
  scope :confirmed, -> { where.not(confirmed_at: nil) }

  def self.find_for_google(auth)
    user = User.find_by(email: auth.info.email)

    unless user
      user = User.create(name:     auth.info.name,
                         provider: auth.provider,
                         uid:      auth.uid,
                         token:    auth.credentials.token,
                         password: Devise.friendly_token[0, 20],
                         meta:     auth.to_yaml)
    end
    user
  end

  def self.from_omniauth(auth)
    user = User.joins(:account).find_by(accounts: {provider: auth["provider"], uid: auth["uid"]})
    

    unless user
      if auth["extra"]["id_info"]["hd"] != ENV["GAPPS_DOMAIN"]
        return nil
    end
      
      user = self.new
      user.email = auth["extra"]["id_info"]["email"]
      user.build_account(
        uid:auth["uid"],
        provider: auth["provider"]
      )
      user.password = Devise.friendly_token[0, 20]
      
     # name と username を決めてもらうやつに飛ばす
    end    
  end

  

  def confirmed?
    confirmed_at.present?
  end

  def disable_two_factor!
    self.otp_required_for_login = false
    otp_backup_codes&.clear
    save!
  end

  def send_devise_notification(notification, *args)
    devise_mailer.send(notification, self, *args).deliver_later
  end

  def setting_default_privacy
    settings.default_privacy || (account.locked? ? 'private' : 'public')
  end

  def setting_boost_modal
    settings.boost_modal
  end

  def setting_auto_play_gif
    settings.auto_play_gif
  end
end
