<?php

namespace App\JWT\Middleware;

use Closure;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

class Authenticate
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
		try {
			$jwt = app('App\JWT\JWT')->verifyRequest($request);
		} catch (CannotDecodeContent | InvalidTokenStructure $e) {

			return response()->json(
                ['error' => 'Token tidak valid.'],
                401,
                ['WWW-Authenticate' => 'error="invalid_token"']
            );

		} catch (RequiredConstraintsViolated $e){
            $violation = $e->violations()[0]->getMessage();
            if ($violation == 'The token is expired') {
                return response()->json(
                    ['error' => 'Token kadaluarsa.'],
                    401,
                    ['WWW-Authenticate' => 'error="token_expired"']
                );
            }

            return response()->json(
                ['error' => 'Token tidak valid.'],
                401,
                ['WWW-Authenticate' => 'error="invalid_token"']
            );
        }

        if ($jwt == false) {
            return response()->json(
                ['error' => 'Login terlebih dahulu'],
                403,
                ['WWW-Authenticate' => 'error="required_token"']
            );
        }

        $request->jwt = $jwt;

        return $next($request);
    }
}
