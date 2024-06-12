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
        $this->middleware('jwt.auth', ['except' => ['login', 'refresh']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
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
            if (!$token = JWTAuth::claims(['email' => $request->input('email')])->attempt($credentials)) {
                return response()->json([
                    'error' => 'Invalid credentials'
                ], 401);
            }
            $user = auth()->user();
            $customClaims = [
                'email' => $user->email,
                'type' => 'refresh'
            ];
            $factory = JWTFactory::customClaims($customClaims)->setTTL(1440);
            $refresh_token = JWTAuth::encode($factory->make())->get();
            $user->update([
                'refresh_token' => $refresh_token
            ]);
            return response()->json([
                'access_token' => $token,
                'refresh_token' => $refresh_token
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not create token'
            ], 500);
        }
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

        $customClaims = [
            'email' => $user->email,
            'type' => 'refresh'
        ];

        try {
            $access_token = JWTAuth::fromUser($user);
            $factory = JWTFactory::customClaims($customClaims)->setTTL(1440);
            $refresh_token = JWTAuth::encode($factory->make())->get();

            $user->update([
                'refresh_token' => $refresh_token
            ]);

            return response()->json([
                'access_token' => $access_token,
                'refresh_token' => $refresh_token,
            ], 201);
        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not create token'
            ], 500);
        }
    }


    public function me()
    {
        return response()->json(auth()->user());
    }

    public function logout()
    {
        try {
            $user = auth()->user();
            $user->update([
                'refresh_token' => null
            ]);

            auth()->logout();

            return response()->json(['message' => 'Successfully logged out']);
        } catch (\Throwable $th) {
            return response()->json($th);
        }
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh(Request $request)
    {
        $refresh_token = $request->input('refresh_token');
        $refresh_token_expired = JWTAuth::setToken($refresh_token)->check();
        if (!$refresh_token_expired) {
            return response()->json([
                'error' => 'Refresh token telah kadaluarsa.'
            ], 401);
        }
        $payload = JWTAuth::setToken($refresh_token)->getPayload();
        $user = User::where('refresh_token', $refresh_token)->first();
        if (!$user) {
            return response()->json([
                'error' => 'Refresh token tidak valid.'
            ], 401);
        }
        if ($user['email'] !== $payload['email']) {
            return response()->json([
                'error' => 'User tidak valid.'
            ], 401);
        }

        try {
            $access_token = JWTAuth::fromUser($user);
            return response()->json([
                'access_token' => $access_token
            ]);
        } catch (JWTException $e) {
            return response()->json([
                'error' => 'Could not create token'
            ], 500);
        }
    }
}
