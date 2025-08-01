<script lang="ts">
import { onMount } from 'svelte';
import { goto } from '$app/navigation';

let username = '';
let password = '';
let error = '';
let loading = false;
let isBootstrapMode = false;
let bootstrapMessage = '';
let mounted = false;

// Client-side validation functions
function validateUsername(username: string): { valid: boolean; error?: string } {
	if (!username) {
		return { valid: false, error: 'Username is required' };
	}
	if (username.length < 3) {
		return { valid: false, error: 'Username must be at least 3 characters' };
	}
	if (username.length > 64) {
		return { valid: false, error: 'Username must be 64 characters or less' };
	}
	if (!/^[A-Za-z0-9_\-]+$/.test(username)) {
		return { valid: false, error: 'Username can only contain letters, numbers, underscores, and hyphens' };
	}
	return { valid: true };
}

function validatePassword(password: string): { valid: boolean; error?: string } {
	if (!password) {
		return { valid: false, error: 'Password is required' };
	}
	if (password.length < 8) {
		return { valid: false, error: 'Password must be at least 8 characters' };
	}
	if (password.length > 128) {
		return { valid: false, error: 'Password must be 128 characters or less' };
	}
	return { valid: true };
}

function validateForm(): { valid: boolean; errors: string[] } {
	const errors: string[] = [];
	
	const usernameValidation = validateUsername(username);
	if (!usernameValidation.valid) {
		errors.push(usernameValidation.error!);
	}
	
	const passwordValidation = validatePassword(password);
	if (!passwordValidation.valid) {
		errors.push(passwordValidation.error!);
	}
	
	return { valid: errors.length === 0, errors };
}

onMount(async () => {
	mounted = true;
	
	// Assume normal login mode by default
	// Bootstrap mode will be detected if login fails with specific error
	isBootstrapMode = false;
});

async function handleSubmit() {
	error = '';
	loading = true;
	
	// Client-side validation
	const validation = validateForm();
	if (!validation.valid) {
		error = validation.errors.join(', ');
		loading = false;
		return;
	}
	
	try {
		if (isBootstrapMode) {
			// Create first admin user
			const res = await fetch('/admin/api/bootstrap', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ username, password })
			});
			
			const data = await res.json();
			if (res.ok) {
				bootstrapMessage = 'Admin user created successfully! You can now log in.';
				isBootstrapMode = false;
				username = '';
				password = '';
			} else {
				error = data.error || 'Failed to create admin user';
			}
		} else {
			// Normal login
			const res = await fetch('/admin/api/login', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ username, password })
			});
			
			const data = await res.json();
			if (res.ok) {
				localStorage.setItem('admin_token', data.token);
				// Store session info for reference
				if (data.sessionId) {
					localStorage.setItem('session_id', data.sessionId);
				}
				goto('/admin/');
			} else {
				// Check if this is a bootstrap mode error
				if (data.error === 'No admin users exist' || data.error === 'Bootstrap mode required') {
					isBootstrapMode = true;
					error = 'No admin users exist. Please create the first admin account.';
				} else {
					error = data.error || 'Login failed';
				}
			}
		}
	} catch (e: any) {
		error = e.message || 'Network error';
	} finally {
		loading = false;
	}
}
</script>

			{#if mounted}
	<div class="login-container">
		<div class="login-card">
			<div class="login-header">
				<h1>CARRELink Admin</h1>
				{#if isBootstrapMode}
					<p class="bootstrap-notice">First-time setup: Create your admin account</p>
				{:else}
					<p>Restricted Access - Authorized Personnel Only</p>
				{/if}
			</div>

			{#if bootstrapMessage}
				<div class="success-message">{bootstrapMessage}</div>
			{/if}

			{#if error}
				<div class="error-message">{error}</div>
			{/if}

			<form on:submit|preventDefault={handleSubmit} class="login-form" autocomplete="on">
				<div class="form-group">
					<label for="username">Username</label>
					<input
						id="username"
						name="username"
						type="text"
						bind:value={username}
						required
						placeholder="Enter username"
						disabled={loading}
						autocomplete="username"
					/>
				</div>

				<div class="form-group">
					<label for="password">Password</label>
					<input
						id="password"
						name="password"
						type="password"
						bind:value={password}
						required
						placeholder="Enter password"
						disabled={loading}
						autocomplete="current-password"
					/>
				</div>

				<button type="submit" disabled={loading} class="login-button">
					{loading ? 'Processing...' : (isBootstrapMode ? 'Create Admin Account' : 'Sign In')}
				</button>
			</form>
		</div>
	</div>
{:else}
	<div class="login-container">
		<div class="loading-spinner"></div>
		<p>Loading login page...</p>
	</div>
{/if}

<style>
.login-container {
	min-height: 100vh;
	display: flex;
	align-items: center;
	justify-content: center;
	        background: #1a1a1a url('/img/bg.jpg') no-repeat center center;
	background-size: cover;
	padding: 2rem;
}

.login-card {
	background: #2d2d2d;
	border-radius: 0.5rem;
	padding: 2.5rem;
	box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
	width: 100%;
	max-width: 400px;
	border: 1px solid #404040;
}

.login-header {
	text-align: center;
	margin-bottom: 2rem;
}

.login-header h1 {
	font-size: 1.8rem;
	font-weight: 700;
	color: #3b82f6;
	margin-bottom: 0.5rem;
	letter-spacing: -0.5px;
}

.login-header p {
	color: #9ca3af;
	font-size: 0.95rem;
	margin: 0;
}

.bootstrap-notice {
	color: #f59e0b !important;
	font-weight: 600;
}

.success-message {
	background: #064e3b;
	color: #d1fae5;
	padding: 1rem;
	border-radius: 0.4rem;
	margin-bottom: 1.5rem;
	border: 1px solid #047857;
}

.error-message {
	background: #7f1d1d;
	color: #fecaca;
	padding: 1rem;
	border-radius: 0.4rem;
	margin-bottom: 1.5rem;
	border: 1px solid #dc2626;
}

.login-form {
	display: flex;
	flex-direction: column;
	gap: 1.5rem;
}

.form-group {
	display: flex;
	flex-direction: column;
	gap: 0.5rem;
}

.form-group label {
	color: #e5e7eb;
	font-weight: 600;
	font-size: 0.9rem;
}

.form-group input {
	background: #1a1a1a;
	border: 1px solid #404040;
	border-radius: 0.4rem;
	padding: 0.75rem 1rem;
	color: #e5e7eb;
	font-size: 1rem;
	transition: border-color 0.15s;
}

.form-group input:focus {
	outline: none;
	border-color: #3b82f6;
	box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.1);
}

.form-group input:disabled {
	opacity: 0.6;
	cursor: not-allowed;
}

.login-button {
	background: #3b82f6;
	color: white;
	border: none;
	border-radius: 0.4rem;
	padding: 0.75rem 1rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	transition: background-color 0.15s;
	margin-top: 0.5rem;
}

.login-button:hover:not(:disabled) {
	background: #2563eb;
}

.login-button:disabled {
	opacity: 0.6;
	cursor: not-allowed;
}


</style> 