<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RegistrationRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return false;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'name' => 'required|string|alpha|max:30',
            /*'lastname' => 'required|string|alpha|max:30',
            'address' => 'required|string|max:100',
            'phone' => 'numeric|digits:7',
            'cellPhone' => 'required|numeric|digits:8',
            'role' => 'required|string|unique:users|max:30',*/
            'email' => 'required|email|unique:users|max:50',
            'password' => 'required|string|min:8'
        ];
    }
}
