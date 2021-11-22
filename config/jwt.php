<?php

return [
	// 'public_key' => env('JWT_PUBLIC_KEY', ''), // Base64
	'private_key' => env('JWT_PRIVATE_KEY', 'ws/o/0yCjXiVKUvLLt0G3WxK82OBTsClvKtFcnGRLfk='), // Base64

	'symmetric_algo' => 'Sha256', // Sha256 , Sha384, Sha512
	// 'asymmetric_algo' => 'Sha256', // Sha256 , Sha384, Sha512

	'accept' => [
		// 'none',
		'symetric',
		// 'asymetric'
	],

	'iss' => env('JWT_ISS', 'https://inilah.com'),
	'exp' => '+1 hour', // A date/time string. Valid formats are explained in {@link https://secure.php.net/manual/en/datetime.formats.php Date and Time Formats}.

	'timezone' => env('APP_TIMEZONE', 'UTC')
];