<?php

namespace App\JWT\Providers;

use Illuminate\Support\ServiceProvider;
use App\JWT\JWT;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->bind(App\JWT\JWT::class, function(){
            return new JWT();
        });
    }
}
