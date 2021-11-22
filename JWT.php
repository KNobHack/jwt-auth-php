<?php

namespace App\JWT;

use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;
use Illuminate\Http\Request;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Signer\Key\InMemory;

use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;

class JWT
{
	/** Issuer */
	protected String $iss;
	/** Issued at */
	protected DateTimeImmutable $iat;
	/** Expire */
	protected DateTimeImmutable $exp;

	protected Builder $builder;
	protected Configuration $configuration;
	protected Token $token;
	protected UnencryptedToken $token_unencrypted;

	protected DateTimeImmutable $now;

	protected Key $private_key;
	protected Key $public_key;

	protected array $config;

	public function __construct() {
		$this->config = require(__DIR__ . '/config/jwt.php');

		$this->private_key = InMemory::base64Encoded($this->config['private_key']);
		// $this->public_key  = InMemory::base64Encoded$this->config['public_key']);
		
		$now       = new DateTimeImmutable();
		$this->now = $now;
		$this->iss = $this->config['iss'];
		$this->iat = $now;
		$this->exp = $now->modify($this->config['exp']);

		$this->build();
	}

	protected function build()
	{
		$symmetric_algo  = "Lcobucci\JWT\Signer\Hmac\\" . $this->config['symmetric_algo'];
		// $asymmetric_algo = "Signer\Rsa\{$this->config['asymmetric_algo']}";

		foreach($this->config['accept'] as $accept){
			if ($accept == 'symetric') {
				$this->configuration = Configuration::forSymmetricSigner(
					new $symmetric_algo(),
					$this->private_key
				);
			}

			// if ($accept == 'asymetric') {
			// 	$this->configuration = Configuration::forAsymmetricSigner(
			// 		new $asymmetric_algo(),
			// 		$this->public_key,
			// 		$this->private_key
			// 	);
			// }

			// if ($accept == 'none') {
			// 	$this->configuration = Configuration::forUnsecuredSigner();
			// }
		}

		$this->builder = $this->configuration->builder();
		$this->builder
			->issuedBy($this->iss)
			->issuedAt($this->iat)
			->expiresAt($this->exp);
	}

	/**
	 * Buat JWT
	 * 
	 * @param array $claims claim yang ingin di sisipkan
	 * @param bool $to_string Jadikan string
	 * @return String|Lcobucci\JWT\Token
	 * @throws RuntimeException
	 */
	public function generate(array $claims, bool $to_string)
	{
		foreach ($claims as $key => $value) {
			if (is_array($value)) throw new RuntimeException("Format array harus satu dimensi. " . print_r($claims), 1);;
			$this->builder->withClaim($key, $value);
		}

		$this->token = $this->builder->getToken(
			$this->configuration->signer(),
			$this->configuration->signingKey()
		);

		if (!$to_string) return $this->token;

		return $this->token->toString();
	}

	/**
	 * Buat JWT dan jadikan array untuk response
	 * 
	 * @return array [
	 *		"access_token"  => a.b.c,
	 *		"token_type"    => "Bearer",
	 *		"expires_in"    => 123,
	 *		"refresh_token" => "abc"
	 *	]
	 * @param array $claims
	 */
	public function forResponse(array $claims, string $refresh_token = '')
	{
		$jwt_token  = $this->generate($claims, true);
		$expires_in = $this->exp->getTimestamp() - $this->iat->getTimestamp();

		return [
            "access_token"  => $jwt_token,
            "token_type"    => "Bearer",
            "expires_in"    => $expires_in,
            "refresh_token" => $refresh_token,
        ];
	}

	/**
	 * Varifikasi token
	 * 
	 * @param string $token token JWT
	 * @return array|false false jika tidak token tidak sah
	 * @throws CannotDecodeContent — When something goes wrong while decoding.
	 * @throws InvalidTokenStructure — When token string structure is invalid.
	 * @throws UnsupportedHeaderFound — When parsed token has an unsupported header.
	 * @throws RequiredConstraintsViolated
	 */
	public function verify(string $token)
	{
		$this->token_unencrypted = $this->configuration->parser()->parse($token);

		$timezone = new DateTimeZone($this->config['timezone']);

		$constraints = [
			new IssuedBy(...[$this->iss]),
			new SignedWith($this->configuration->signer(), $this->configuration->signingKey()),
			new LooseValidAt(new SystemClock($timezone)),
		];

		// $constraints = $this->configuration->validationConstraints();
		// var_dump($constraints);die;

		$this->configuration->validator()->assert(
			$this->token_unencrypted,
			...$constraints
		);

		$this->token_unencrypted = $this->configuration->parser()->parse($token);

		$user = $this->token_unencrypted->claims()->all();

		unset($user['iss']);
		unset($user['iat']);
		unset($user['exp']);

		return $user;
	}

	/**
	 * Verifikasi token dari Class Request Laravel
	 * 
	 * @param Illuminate\Http\Request
	 * @return array|false false jika tidak token tidak sah
	 * @throws CannotDecodeContent — When something goes wrong while decoding.
	 * @throws InvalidTokenStructure — When token string structure is invalid.
	 * @throws UnsupportedHeaderFound — When parsed token has an unsupported header.
	 * @throws RequiredConstraintsViolated
	 */
	public function verifyRequest(Request $request)
	{
		$token = $request->bearerToken();

		if ($token == null) {
			return false;
		}

		return $this->verify($token);
	}
}