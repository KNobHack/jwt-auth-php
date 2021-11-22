<?php

namespace App\JWT\Middleware;

use App\JWT\JWT;
use Closure;
use Illuminate\Contracts\Auth\Factory as Auth;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

class Authenticate
{
    /**
     * The authentication guard factory instance.
     *
     * @var \Illuminate\Contracts\Auth\Factory
     */
    protected $auth;

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Contracts\Auth\Factory  $auth
     * @return void
     */
    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next, $wajib = false)
    {
        if ($this->auth->guard()->guest() && $wajib) {
            return $this->responseGuest();
        }

        return $next($request);
    }

    private function responseGuest()
    {
        return response()->json(
            ['error' => 'Login terlebih dahulu'],
            403,
            ['WWW-Authenticate' => 'error="required_token"']
        );
    }
}
