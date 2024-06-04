<?php

use App\Http\Controllers\API\Auth\LoginController;
use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\StuffController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::group(['middleware' => 'api','prefix' => 'auth'], function() {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/refresh', [AuthController::class, 'refresh']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/me', [AuthController::class, 'me']);
});

// Route::get('/user', [AuthController::class, 'getAuthenticatedUser']);

// Route::middleware(['jwt.auth','auth:api'])->group(function () {
//     Route::resource('stuff', StuffController::class);
// });

