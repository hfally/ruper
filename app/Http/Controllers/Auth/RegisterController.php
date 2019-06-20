<?php

namespace App\Http\Controllers\Auth;

use App\Mail\LoginFailed;
use App\User;
use App\Http\Controllers\Controller;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Auth\RegistersUsers;
use Illuminate\Foundation\Auth\ThrottlesLogins;

class RegisterController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Register Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users as well as their
    | validation and creation. By default this controller uses a trait to
    | provide this functionality without requiring any additional code.
    |
    */

    use RegistersUsers, ThrottlesLogins;

    /**
     * Where to redirect users after registration.
     *
     * @var string
     */
    protected $redirectTo = '/home';
    protected $maxAttempts = 3;
    protected $decayMinutes = 5;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware(['guest']);
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
//    protected function validator(array $data)
//    {
//        return Validator::make($data, [
//            'name' => ['required', 'string', 'max:255'],
//            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
//            'password' => ['required', 'string', 'min:16', 'alpha_num', 'regex:/[@$!%*#?&]/', 'confirmed'],
//        ]);
//    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return \App\User
     */
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);
    }

    public function register(Request $request)
    {
        // Temp validate email
        $email_validator = Validator::make(['email' => $request->email], [
            'email' => 'required|email'
        ]);

        if (!$email_validator->fails()) {
            $this->incrementLoginAttempts($request);
        }

        if($this->hasTooManyLoginAttempts($request)) {
            $this->sendMail($request->email);
            $this->fireLockoutEvent($request);
            return $this->sendLockoutResponse($request);
        }

        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => [
                'required',
                'min:16',
                'regex:/^[A-Z]{2}/',
                'regex:/[a-z]/',
                'regex:/\d{3}/',
                'regex:/[@$!%*#?&]{2}/',
                'confirmed',
            ],
        ], [
            'password.regex' => 'Password must include these
                <ul>
                    <li>2 uppercase as first characters</li>
                    <li>at least one lowercase character</li>
                    <li>3 numbers</li>
                    <li>2 symbols</li>
                </ul>'
        ]);

        $data = [
            'email' => $request->email,
            'password' => $request->passord,
            'name' => $request->name
        ];

        event(new Registered($user = $this->create($request->all())));

        $this->guard()->login($user);

        return $this->registered($request, $user)
            ?: redirect($this->redirectPath());
    }

    public function username()
    {
        return 'email';
    }

    public function sendMail($email)
    {
        // So it doesn't break application
        try {
            Mail::to($email)->send(new LoginFailed());
        } catch (\Exception $e) {
            //
        }
    }
}
