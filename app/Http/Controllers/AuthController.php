<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;

class AuthController extends Controller
{
    private string $credFile = 'admin_credentials.json';

    private function ensureCredFileExists(): void
    {
        if (!Storage::exists($this->credFile)) {
            $default = [
                'username' => 'admin',
                'password_hash' => Hash::make('password'),
                'updated_at' => now()->toDateTimeString(),
            ];
            Storage::put($this->credFile, json_encode($default, JSON_PRETTY_PRINT));
        }
    }

    private function getCred(): array
    {
        $this->ensureCredFileExists();
        $raw = Storage::get($this->credFile);
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
    }

    private function saveCred(array $data): void
    {
        $data['updated_at'] = now()->toDateTimeString();
        Storage::put($this->credFile, json_encode($data, JSON_PRETTY_PRINT));
    }

    public function showLoginForm()
    {
        return view('admin.login');
    }

    public function login(Request $request)
    {
        $request->validate([
            'username' => 'required|string|max:50',
            'password' => 'required|string|min:4',
        ]);

        $cred = $this->getCred();

        $username = trim((string) $request->input('username'));
        $password = (string) $request->input('password');

        $okUser = isset($cred['username']) && $username === $cred['username'];
        $okPass = isset($cred['password_hash']) && Hash::check($password, $cred['password_hash']);

        if (!$okUser || !$okPass) {
            return back()
                ->withInput($request->only('username'))
                ->withErrors(['login' => 'Username atau password salah.']);
        }

        session([
            'admin_logged_in' => true,
            'admin_name' => $username,
        ]);

        return redirect()->route('admin.dashboard');
    }

    public function updatePassword(Request $request)
    {
        if (!$request->session()->get('admin_logged_in')) {
            return redirect()->route('admin.login.form');
        }

        $request->validate([
            'old_password' => 'required|string',
            'new_password' => 'required|string|min:6|confirmed',
        ]);

        $cred = $this->getCred();

        // validasi password lama
        if (!isset($cred['password_hash']) || !Hash::check((string)$request->old_password, $cred['password_hash'])) {
            return back()->with('success', 'Password lama salah.');
        }

        // simpan password baru (hash)
        $cred['password_hash'] = Hash::make((string)$request->new_password);
        $this->saveCred($cred);

        return redirect()->route('admin.dashboard')->with('success', 'Password berhasil diubah.');
    }

    public function logout(Request $request)
    {
        $request->session()->forget(['admin_logged_in', 'admin_name']);
        return redirect()->route('admin.login.form');
    }
}
