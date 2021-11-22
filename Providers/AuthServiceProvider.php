<?php

namespace App\JWT\Providers;

use Illuminate\Support\ServiceProvider;
use App\JWT\JWT;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\Request;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->bind(JWT::class, function(){
            return new JWT();
        });

        $this->app['auth']->viaRequest('api', function ($request) {

            $jwt = app(JWT::class)->verifyRequest($request, false);

            if ($jwt !== false) {
                $this->app->request->jwt = $jwt;
                return new GenericUser($jwt);
            }
        });
    }
}
