<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\RegistrationRequest;
use App\Http\Requests\LoginRequest;

class AuthController extends Controller
{
    public function register(RegistrationRequest $request)
    {
        try{
            /*$validateUser = $request->validated();
            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }*/

            $data = $request->all();
            $data['password'] = Hash::make($request->password);
            $user = User::create($data);

            $token = $user->createToken('API TOKEN')->plainTextToken;
            return response()->json([
                'status' => true,
                'user' => $user,
                'token' => $token
            ], 200);
        }
        catch(\Throwable $th){
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    public function login(LoginRequest $request){
        try{
            $validateUser = $request->validated();
            if($validateUser->fails()){
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            if(!Auth::attempt($request->only(['email', 'password']))){
                return response()->json([
                    'status' => false,
                    'message' => 'Email or Password does not match with our record.',
                ], 401);
            }

            $user = User::where('email', $request->email)->first();

            $token = $user->createToken('API TOKEN')->plainTextToken;
            return response()->json([
                'status' => true,
                'message' => 'Login success',
                'token' => $token
            ], 200);
        }
        catch(\Throwable $th){
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    public function logout(Request $request){
        try{
            $request->user()->currentAccessToken()->delete();
            return response()->json([
                'status' => true,
                'message' => 'Logout success'
            ], 200);
        }
        catch(\Throwable $th){
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }
}
