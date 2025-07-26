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

onMount(async () => {
	mounted = true;
	
	// Check if we're in bootstrap mode (no admin users exist)
	try {
		const res = await fetch('/admin/api/bootstrap', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ username: 'test', password: 'test' })
		});
		
		if (res.status === 400) {
			const data = await res.json();
			if (data.error === 'Not Allowed') {
				isBootstrapMode = false;
			} else {
				isBootstrapMode = true;
			}
		} else {
			isBootstrapMode = true;
		}
	} catch (e) {
		// If we can't reach the bootstrap endpoint, assume normal login mode
		isBootstrapMode = false;
	}
});

async function handleSubmit() {
	error = '';
	loading = true;
	
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
				goto('/admin/');
			} else {
				error = data.error || 'Login failed';
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
					<p>Sign in to manage users and ACLs</p>
				{/if}
			</div>

			{#if bootstrapMessage}
				<div class="success-message">{bootstrapMessage}</div>
			{/if}

			{#if error}
				<div class="error-message">{error}</div>
			{/if}

			<form on:submit|preventDefault={handleSubmit} class="login-form">
				<div class="form-group">
					<label for="username">Username</label>
					<input
						id="username"
						type="text"
						bind:value={username}
						required
						placeholder="Enter username"
						disabled={loading}
					/>
				</div>

				<div class="form-group">
					<label for="password">Password</label>
					<input
						id="password"
						type="password"
						bind:value={password}
						required
						placeholder="Enter password"
						disabled={loading}
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
	background: linear-gradient(135deg, #23283a 0%, #181c24 100%);
	padding: 2rem;
}

.login-card {
	background: #23283a;
	border-radius: 1rem;
	padding: 3rem;
	box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
	width: 100%;
	max-width: 400px;
	border: 1px solid #374151;
}

.login-header {
	text-align: center;
	margin-bottom: 2rem;
}

.login-header h1 {
	font-size: 2rem;
	font-weight: 800;
	color: #60a5fa;
	margin-bottom: 0.5rem;
	letter-spacing: -1px;
}

.login-header p {
	color: #9ca3af;
	font-size: 1rem;
	margin: 0;
}

.bootstrap-notice {
	color: #fbbf24 !important;
	font-weight: 600;
}

.success-message {
	background: #065f46;
	color: #d1fae5;
	padding: 1rem;
	border-radius: 0.5rem;
	margin-bottom: 1.5rem;
	border: 1px solid #10b981;
}

.error-message {
	background: #7f1d1d;
	color: #fecaca;
	padding: 1rem;
	border-radius: 0.5rem;
	margin-bottom: 1.5rem;
	border: 1px solid #ef4444;
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
	background: #1e293b;
	border: 1px solid #374151;
	border-radius: 0.5rem;
	padding: 0.75rem 1rem;
	color: #e5e7eb;
	font-size: 1rem;
	transition: border-color 0.2s;
}

.form-group input:focus {
	outline: none;
	border-color: #60a5fa;
	box-shadow: 0 0 0 3px rgba(96, 165, 250, 0.1);
}

.form-group input:disabled {
	opacity: 0.6;
	cursor: not-allowed;
}

.login-button {
	background: #60a5fa;
	color: white;
	border: none;
	border-radius: 0.5rem;
	padding: 0.75rem 1rem;
	font-size: 1rem;
	font-weight: 600;
	cursor: pointer;
	transition: background-color 0.2s;
	margin-top: 0.5rem;
}

.login-button:hover:not(:disabled) {
	background: #3b82f6;
}

.login-button:disabled {
	opacity: 0.6;
	cursor: not-allowed;
}
</style> 