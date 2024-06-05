<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Facades\JWTFactory;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'refresh']]);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|min:8'
        ], [
            'email.required' => 'Email tidak boleh kosong.',
            'email.email' => 'Harus tipe email!',
            'password.required' => 'Password tidak boleh kosong.',
            'password.min' => 'Password harus terdiri dari minimal 8 karakter.'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed.',
                'errors' => $validator->errors()
            ], 422);
        }

        $credentials = $request->only('email', 'password');
        try {
            if (!JWTAuth::attempt($credentials)) {
                return response()->json([
                    'error' => 'Invalid credentials'
                ], 401);
            }

            $user = auth()->user();
            $user_update = User::find($user->id);

            $customClaims = [
                'id' => $user->id,
                'name' => $user->name,
                'type' => 'refresh'
            ];

            $accessToken = JWTAuth::fromUser($user);
            $factory = JWTFactory::customClaims($customClaims)->setTTL(1440);
            $refreshToken = JWTAuth::encode($factory->make())->get();

            $user_update->update([
                'refresh_token' => $refreshToken
            ]);

            return response()->json([
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
                'expires_in' => 1 * 60,
                'refresh_token' => $refreshToken,
                'refresh_expires_in' => 24 * 60 * 60
            ]);

        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not create token'
            ], 500);
        }

        return response()->json(compact('payload'));
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ], [
            'name.required' => 'Nama tidak boleh kosong.',
            'name.string' => 'Nama harus berupa string.',
            'name.max' => 'Nama tidak boleh lebih dari 255 karakter.',
            'email.required' => 'Email tidak boleh kosong.',
            'email.string' => 'Email harus berupa string.',
            'email.email' => 'Harus format email yang valid.',
            'email.max' => 'Email tidak boleh lebih dari 255 karakter.',
            'email.unique' => 'Email sudah terdaftar.',
            'password.required' => 'Password tidak boleh kosong.',
            'password.string' => 'Password harus berupa string.',
            'password.min' => 'Password harus terdiri dari minimal 8 karakter.',
            'password.confirmed' => 'Konfirmasi password tidak cocok.',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Validation failed.',
                'errors' => $validator->errors()
            ], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $user_update = User::find($user->id);

        $customClaims = [
            'id' => $user->id,
            'name' => $user->name,
            'type' => 'refresh'
        ];

        $accessToken = JWTAuth::fromUser($user);
        $factory = JWTFactory::customClaims($customClaims)->setTTL(1440);
        $refreshToken = JWTAuth::encode($factory->make())->get();

        $user_update->update([
            'refresh_token' => $refreshToken
        ]);

        return response()->json([
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 1 * 60,
            'refresh_token' => $refreshToken,
            'refresh_expires_in' => 24 * 60 * 60
        ], 201);
    }


    public function me()
    {
        return response()->json(auth()->user());
    }

    public function logout()
    {
        $user = auth()->user();
        $user_update = User::find($user->id);
        $user_update->update([
            'refresh_token' => null
        ]);

        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh(Request $request)
    {
        $refreshToken = $request->input('refresh_token');

        try {
            $payload = JWTAuth::setToken($refreshToken)->getPayload();

            if ($payload['type'] !== 'refresh') {
                return response()->json(['error' => 'Invalid token type'], 401);
            }

            $user = User::find($payload['id']);

            if (!$user) {
                return response()->json(['error' => 'Invalid refresh token'], 401);
            }

            if($user->refresh_token !== $refreshToken){
                return response()->json(['error' => 'Tokens do not match'], 401);
            }

            $token = JWTAuth::fromUser($user);

            return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'expires_in' => 1 * 60,
            ]);
        } catch (TokenExpiredException $e) {
            return response()->json(['error' => 'Refresh token expired'], 401);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Invalid refresh token'], 401);
        }
    }
}
