<?php

namespace RainLoop\Providers;

class ChangePassword extends \RainLoop\Providers\AbstractProvider
{
	/**
	 * @var \RainLoop\Actions
	 */
	private $oActions;

	/**
	 * @var \RainLoop\Providers\ChangePassword\ChangePasswordInterface
	 */
	private $oDriver;

	/**
	 * @var bool
	 */
	private $bCheckWeak;

	/**
	 * @param \RainLoop\Actions $oActions
	 * @param \RainLoop\Providers\ChangePassword\ChangePasswordInterface|null $oDriver = null
	 * @param bool $bCheckWeak = true
	 *
	 * @return void
	 */
	public function __construct($oActions, $oDriver = null, $bCheckWeak = true)
	{
		$this->oActions = $oActions;
		$this->oDriver = $oDriver;
		$this->bCheckWeak = !!$bCheckWeak;
	}

	/**
	 * @param \RainLoop\Account $oAccount
	 *
	 * @return bool
	 */
	public function PasswordChangePossibility($oAccount)
	{
		return $this->IsActive() &&
			$oAccount instanceof \RainLoop\Account &&
			$this->oDriver && $this->oDriver->PasswordChangePossibility($oAccount)
		;
	}

	/**
	 * @param \RainLoop\Account $oAccount
	 * @param string $sPrevPassword
	 * @param string $sNewPassword
	 */
	public function ChangePassword(\RainLoop\Account $oAccount, $sPrevPassword, $sNewPassword)
	{
		$mResult = false;

		if ($this->oDriver instanceof \RainLoop\Providers\ChangePassword\ChangePasswordInterface &&
			$this->PasswordChangePossibility($oAccount))
		{
			if ($sPrevPassword !== $oAccount->Password())
			{
				throw new \RainLoop\Exceptions\ClientException(\RainLoop\Notifications::CurrentPasswordIncorrect);
			}

			$sPasswordForCheck = \trim($sNewPassword);

			// check password rules
			if (strlen($sPasswordForCheck) < 8 ||
				!preg_match('/[A-Z]/', $sPasswordForCheck)||
				!preg_match('/[a-z]/', $sPasswordForCheck)||
				!preg_match('/[0-9]/', $sPasswordForCheck))
			{
				throw new \RainLoop\Exceptions\ClientException("Das neue Passwort muss mindestens 8 Zeichen lang sein, einen Großbuchstaben, einen Kleinbuchstaben und eine Zahl enthalten.");
			}

			if (!\MailSo\Base\Utils::PasswordWeaknessCheck($sPasswordForCheck))
			{
				throw new \RainLoop\Exceptions\ClientException(\RainLoop\Notifications::NewPasswordWeak);
			}

			if (!$this->oDriver->ChangePassword($oAccount, $sPrevPassword, $sNewPassword))
			{
				throw new \RainLoop\Exceptions\ClientException(\RainLoop\Notifications::CouldNotSaveNewPassword);
			}

			$oAccount->SetPassword($sNewPassword);
			$this->oActions->SetAuthToken($oAccount);

			$mResult = $this->oActions->GetSpecAuthToken();
		}
		else
		{
			throw new \RainLoop\Exceptions\ClientException(\RainLoop\Notifications::CouldNotSaveNewPassword);
		}

		return $mResult;
	}

	/**
	 * @return bool
	 */
	public function IsActive()
	{
		return $this->oDriver instanceof \RainLoop\Providers\ChangePassword\ChangePasswordInterface;
	}
}
