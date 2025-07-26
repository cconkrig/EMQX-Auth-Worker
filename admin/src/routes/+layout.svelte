<script lang="ts">
import { page } from '$app/stores';
import { onMount, onDestroy } from 'svelte';
import { goto } from '$app/navigation';

let isAuthenticated = false;
let isLoading = true;
let mounted = false;

// Session timeout management
let sessionTimeoutId: number | null = null;
const SESSION_TIMEOUT = 15 * 60 * 1000; // 15 minutes in milliseconds

// Expose resetSessionTimeout function globally for child components
if (typeof window !== 'undefined') {
	(window as any).resetSessionTimeout = resetSessionTimeout;
}

// Reactive statement to handle authentication when pathname changes
$: if (mounted && $page.url.pathname !== '/admin/login') {
	checkAuthentication();
}

onMount(() => {
	mounted = true;
	
	// If we're already on the login page, don't check authentication
	if ($page.url.pathname === '/admin/login') {
		isLoading = false;
		return;
	}
	
	// Check authentication for initial load
	checkAuthentication();
	
	// Set up activity tracking for session timeout
	setupSessionTimeout();
});

onDestroy(() => {
	// Clean up timeout when component is destroyed
	if (sessionTimeoutId) {
		clearTimeout(sessionTimeoutId);
	}
	
	// Remove event listeners
	removeActivityListeners();
	
	// Clean up global function
	if (typeof window !== 'undefined') {
		delete (window as any).resetSessionTimeout;
	}
});

function setupSessionTimeout() {
	// Reset the session timeout
	resetSessionTimeout();
	
	// Add event listeners for user activity
	addActivityListeners();
}

function resetSessionTimeout() {
	// Clear existing timeout
	if (sessionTimeoutId) {
		clearTimeout(sessionTimeoutId);
	}
	
	// Set new timeout
	sessionTimeoutId = setTimeout(() => {
		console.log('Session expired due to inactivity');
		logout('Session expired due to inactivity');
	}, SESSION_TIMEOUT);
}

function addActivityListeners() {
	// Track various user activities
	const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
	
	events.forEach(event => {
		document.addEventListener(event, resetSessionTimeout, true);
	});
	
	// Track page visibility changes
	document.addEventListener('visibilitychange', () => {
		if (!document.hidden) {
			resetSessionTimeout();
		}
	});
}

function removeActivityListeners() {
	// Remove all activity event listeners
	const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
	
	events.forEach(event => {
		document.removeEventListener(event, resetSessionTimeout, true);
	});
	
	document.removeEventListener('visibilitychange', () => {
		if (!document.hidden) {
			resetSessionTimeout();
		}
	});
}

function checkAuthentication() {
	const token = localStorage.getItem('admin_token');
	console.log('Checking authentication with token:', token ? token.substring(0, 20) + '...' : 'null');
	
	if (!token) {
		console.log('No token found, redirecting to login');
		goto('/admin/login');
		return;
	}
	
	// Reset state for new check
	isLoading = true;
	isAuthenticated = false;
	
	// Verify token is still valid by making a test request
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
	
	fetch('/admin/api/users', {
		headers: { Authorization: `Bearer ${token}` },
		signal: controller.signal
	}).then(res => {
		clearTimeout(timeoutId);
		console.log('Auth check response status:', res.status);
		if (res.ok) {
			console.log('Authentication successful');
			isAuthenticated = true;
			// Reset session timeout when authentication is successful
			resetSessionTimeout();
		} else {
			console.log('Authentication failed, redirecting to login');
			localStorage.removeItem('admin_token');
			goto('/admin/login');
		}
	}).catch((error) => {
		clearTimeout(timeoutId);
		console.log('Authentication error:', error);
		localStorage.removeItem('admin_token');
		goto('/admin/login');
	}).finally(() => {
		isLoading = false;
	});
}

function logout(reason = 'User logged out') {
	// Clean up session timeout
	if (sessionTimeoutId) {
		clearTimeout(sessionTimeoutId);
		sessionTimeoutId = null;
	}
	
	// Remove activity listeners
	removeActivityListeners();
	
	// Clear token and redirect
	localStorage.removeItem('admin_token');
	
	// Show logout reason if it's due to timeout
	if (reason.includes('Session expired')) {
		alert('You have been logged out due to inactivity. Please log in again.');
	}
	
	goto('/admin/login');
}
</script>

{#if !mounted}
	<div class="loading-container">
		<div class="loading-spinner"></div>
		<p>Loading...</p>
	</div>
{:else if $page.url.pathname === '/admin/login'}
	<!-- Login page - render without authentication check -->
	<slot />
{:else if isLoading}
	<div class="loading-container">
		<div class="loading-spinner"></div>
		<p>Loading...</p>
	</div>
{:else if isAuthenticated}
	<main class="admin-root">
		<nav class="sidebar">
			<div class="sidebar-title">CARRELink Admin</div>
			<ul class="sidebar-nav">
				<li><a href="/admin/" class:active={$page.url.pathname === '/admin/'}>Dashboard</a></li>
				<li><a href="/admin/users" class:active={$page.url.pathname === '/admin/users'}>Users</a></li>
				<li><a href="/admin/acls" class:active={$page.url.pathname === '/admin/acls'}>ACLs</a></li>
				<li><button type="button" class="logout-link" on:click={() => logout()}>Logout</button></li>
			</ul>
		</nav>
		<section class="main-content">
			<slot />
		</section>
	</main>
{:else}
	<div class="loading-container">
		<div class="loading-spinner"></div>
		<p>Redirecting to login...</p>
	</div>
{/if}

<style>
:global(html) {
	font-family: 'Inter', 'Roboto', 'Segoe UI', 'Helvetica Neue', Arial, 'Liberation Sans', 'sans-serif';
	background: #1a1a1a;
	font-size: 16px;
	color: #e5e7eb;
}
.admin-root {
	display: flex;
	min-height: 100vh;
	background: #1a1a1a;
}
.sidebar {
	width: 240px;
	background: #2d2d2d;
	color: #e5e7eb;
	display: flex;
	flex-direction: column;
	align-items: stretch;
	padding: 2rem 1.2rem 1.2rem 1.2rem;
	box-shadow: 1px 0 8px rgba(0,0,0,0.2);
	z-index: 10;
	border-right: 1px solid #404040;
}
.sidebar-title {
	font-size: 1.4rem;
	font-weight: 700;
	margin-bottom: 2.5rem;
	letter-spacing: -0.5px;
	text-align: center;
	color: #3b82f6;
}
.sidebar-nav {
	list-style: none;
	padding: 0;
	margin: 0;
	display: flex;
	flex-direction: column;
	gap: 0.5rem;
}
.sidebar-nav li {
	padding: 0;
	border-radius: 0.4rem;
	font-size: 1rem;
	font-weight: 500;
	cursor: pointer;
	transition: background 0.15s, color 0.15s;
	color: #d1d5db;
}
.sidebar-nav li a {
	color: inherit;
	text-decoration: none;
	display: block;
	width: 100%;
	padding: 0.7rem 1rem;
	border-radius: 0.4rem;
	transition: background 0.15s, color 0.15s;
}
.sidebar-nav li a.active, .sidebar-nav li a:hover {
	background: #404040;
	color: #3b82f6;
}
.sidebar-nav .logout-link {
	margin-top: auto;
	background: #dc2626;
	color: #fff;
	text-align: center;
	font-weight: 600;
	transition: background 0.15s;
	border: none;
	border-radius: 0.4rem;
	padding: 0.7rem 1rem;
	font-size: 1rem;
	cursor: pointer;
	width: 100%;
}
.sidebar-nav .logout-link:hover {
	background: #b91c1c;
}
.main-content {
	flex: 1;
	padding: 3rem 3rem 2rem 3rem;
	display: flex;
	flex-direction: column;
	gap: 2rem;
	background: transparent;
	min-height: 100vh;
}

.loading-container {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	min-height: 100vh;
	background: #1a1a1a;
	color: #e5e7eb;
}

.loading-spinner {
	width: 32px;
	height: 32px;
	border: 3px solid #404040;
	border-top: 3px solid #3b82f6;
	border-radius: 50%;
	animation: spin 1s linear infinite;
	margin-bottom: 1rem;
}

@keyframes spin {
	0% { transform: rotate(0deg); }
	100% { transform: rotate(360deg); }
}
</style> 