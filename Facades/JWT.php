<?php

namespace App\JWT\Facades;

use App\JWT\JWT as JWTClass;
use Illuminate\Support\Facades\Facade;

class JWT extends Facade
{
	protected static function getFacadeAccessor()
	{
		return JWTClass::class;
	}
}
