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
		<!-- Floating geometric elements -->
		<div class="floating-element element-1"></div>
		<div class="floating-element element-2"></div>
		<div class="floating-element element-3"></div>
		<div class="floating-element element-4"></div>
		
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
	background: #0a0a0a;
	padding: 2rem;
	position: relative;
	overflow: hidden;
}

.login-container::before {
	content: '';
	position: absolute;
	top: 0;
	left: 0;
	right: 0;
	bottom: 0;
	background: 
		radial-gradient(circle at 20% 80%, rgba(59, 130, 246, 0.15) 0%, transparent 50%),
		radial-gradient(circle at 80% 20%, rgba(16, 185, 129, 0.1) 0%, transparent 50%),
		radial-gradient(circle at 40% 40%, rgba(139, 92, 246, 0.1) 0%, transparent 50%);
	animation: backgroundShift 20s ease-in-out infinite;
}

.login-container::after {
	content: '';
	position: absolute;
	top: 0;
	left: 0;
	right: 0;
	bottom: 0;
	background-image: 
		linear-gradient(90deg, transparent 98%, rgba(59, 130, 246, 0.1) 100%),
		linear-gradient(0deg, transparent 98%, rgba(59, 130, 246, 0.1) 100%);
	background-size: 50px 50px;
	animation: gridMove 15s linear infinite;
	opacity: 0.3;
}

@keyframes backgroundShift {
	0%, 100% { transform: scale(1) rotate(0deg); }
	50% { transform: scale(1.1) rotate(1deg); }
}

@keyframes gridMove {
	0% { transform: translate(0, 0); }
	100% { transform: translate(50px, 50px); }
}

/* Floating geometric elements */
.floating-element {
	position: absolute;
	opacity: 0.1;
	z-index: 1;
}

.element-1 {
	width: 100px;
	height: 100px;
	top: 10%;
	left: 10%;
	background: linear-gradient(45deg, #3b82f6, transparent);
	clip-path: polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%);
	animation: float1 8s ease-in-out infinite;
}

.element-2 {
	width: 60px;
	height: 60px;
	top: 70%;
	right: 15%;
	background: linear-gradient(45deg, #10b981, transparent);
	clip-path: polygon(25% 0%, 100% 0%, 75% 100%, 0% 100%);
	animation: float2 12s ease-in-out infinite;
}

.element-3 {
	width: 80px;
	height: 80px;
	top: 20%;
	right: 20%;
	background: linear-gradient(45deg, #8b5cf6, transparent);
	border-radius: 50%;
	animation: float3 10s ease-in-out infinite;
}

.element-4 {
	width: 120px;
	height: 40px;
	bottom: 20%;
	left: 20%;
	background: linear-gradient(90deg, #3b82f6, #10b981);
	clip-path: polygon(0% 0%, 100% 0%, 80% 100%, 20% 100%);
	animation: float4 15s ease-in-out infinite;
}

@keyframes float1 {
	0%, 100% { transform: translateY(0px) rotate(0deg); }
	50% { transform: translateY(-20px) rotate(180deg); }
}

@keyframes float2 {
	0%, 100% { transform: translateY(0px) rotate(0deg); }
	50% { transform: translateY(15px) rotate(-90deg); }
}

@keyframes float3 {
	0%, 100% { transform: translateY(0px) scale(1); }
	50% { transform: translateY(-30px) scale(1.2); }
}

@keyframes float4 {
	0%, 100% { transform: translateY(0px) rotate(0deg); }
	50% { transform: translateY(25px) rotate(45deg); }
}

.login-card {
	background: rgba(45, 45, 45, 0.9);
	backdrop-filter: blur(20px);
	border-radius: 1rem;
	padding: 2.5rem;
	box-shadow: 
		0 8px 32px rgba(0, 0, 0, 0.4),
		0 0 0 1px rgba(59, 130, 246, 0.1),
		inset 0 1px 0 rgba(255, 255, 255, 0.1);
	width: 100%;
	max-width: 400px;
	border: 1px solid rgba(59, 130, 246, 0.2);
	position: relative;
	z-index: 10;
}

.login-card::before {
	content: '';
	position: absolute;
	top: -1px;
	left: -1px;
	right: -1px;
	bottom: -1px;
	background: linear-gradient(45deg, #3b82f6, #10b981, #8b5cf6, #3b82f6);
	border-radius: 1rem;
	z-index: -1;
	opacity: 0.3;
	animation: borderGlow 3s ease-in-out infinite;
}

@keyframes borderGlow {
	0%, 100% { opacity: 0.3; }
	50% { opacity: 0.6; }
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