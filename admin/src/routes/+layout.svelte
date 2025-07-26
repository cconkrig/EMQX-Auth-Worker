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
	
	if (!token) {
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
		if (res.ok) {
			isAuthenticated = true;
			// Reset session timeout when authentication is successful
			resetSessionTimeout();
		} else {
			localStorage.removeItem('admin_token');
			goto('/admin/login');
		}
	}).catch((error) => {
		clearTimeout(timeoutId);
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
	background: #181c24;
	font-size: 18px;
	color: #e5e7eb;
}
.admin-root {
	display: flex;
	min-height: 100vh;
	background: linear-gradient(135deg, #23283a 0%, #181c24 100%);
}
.sidebar {
	width: 240px;
	background: #23283a;
	color: #e5e7eb;
	display: flex;
	flex-direction: column;
	align-items: stretch;
	padding: 2rem 1.2rem 1.2rem 1.2rem;
	box-shadow: 2px 0 16px rgba(0,0,0,0.12);
	z-index: 10;
}
.sidebar-title {
	font-size: 1.5rem;
	font-weight: 800;
	margin-bottom: 2.5rem;
	letter-spacing: -1px;
	text-align: center;
	color: #60a5fa;
}
.sidebar-nav {
	list-style: none;
	padding: 0;
	margin: 0;
	display: flex;
	flex-direction: column;
	gap: 1.2rem;
}
.sidebar-nav li {
	padding: 0.7rem 1rem;
	border-radius: 0.6rem;
	font-size: 1.1rem;
	font-weight: 600;
	cursor: pointer;
	transition: background 0.18s, color 0.18s;
	color: #e5e7eb;
}
.sidebar-nav li a {
	color: inherit;
	text-decoration: none;
	display: block;
	width: 100%;
}
.sidebar-nav li a.active, .sidebar-nav li a:hover {
	background: #1e293b;
	color: #60a5fa;
}
.sidebar-nav .logout-link {
	margin-top: auto;
	background: #dc2626;
	color: #fff;
	text-align: center;
	font-weight: 700;
	transition: background 0.18s;
	border: none;
	border-radius: 0.6rem;
	padding: 0.7rem 1rem;
	font-size: 1.1rem;
	cursor: pointer;
	width: 100%;
}
.sidebar-nav .logout-link:hover {
	background: #b91c1c;
}
.main-content {
	flex: 1;
	padding: 3.5rem 3.5rem 2.5rem 3.5rem;
	display: flex;
	flex-direction: column;
	gap: 2.5rem;
	background: transparent;
	min-height: 100vh;
}

.loading-container {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	min-height: 100vh;
	background: linear-gradient(135deg, #23283a 0%, #181c24 100%);
	color: #e5e7eb;
}

.loading-spinner {
	width: 40px;
	height: 40px;
	border: 4px solid #374151;
	border-top: 4px solid #60a5fa;
	border-radius: 50%;
	animation: spin 1s linear infinite;
	margin-bottom: 1rem;
}

@keyframes spin {
	0% { transform: rotate(0deg); }
	100% { transform: rotate(360deg); }
}
</style> 