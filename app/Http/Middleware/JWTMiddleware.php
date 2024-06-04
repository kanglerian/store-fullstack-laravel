<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Facades\JWTAuth;

class JWTMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
        } catch (TokenExpiredException $e) {
            return response()->json(['error' => 'Sesi habis, silahkan lakukan login kembali.'], 401);
        } catch (TokenInvalidException $e) {
            return response()->json(['error' => 'Token tidak cocok.'], 401);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Token kosong.'], 401);
        }

        if (!$user) {
            return response()->json(['error' => 'Akun tidak ditemukan!'], 404);
        }

        $request->user = $user;

        return $next($request);
    }
}
