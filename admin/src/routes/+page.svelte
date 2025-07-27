<script lang="ts">
import { onMount } from 'svelte';

let sessionInfo: any = null;
let loading = false;
let error = '';

onMount(async () => {
	await loadSessionInfo();
});

async function loadSessionInfo() {
	loading = true;
	error = '';
	
	try {
		if (typeof window !== 'undefined' && (window as any).getSessionInfo) {
			sessionInfo = await (window as any).getSessionInfo();
		}
	} catch (e: any) {
		error = e.message || 'Failed to load session info';
	} finally {
		loading = false;
	}
}

async function logoutAllSessions() {
	if (!confirm('Are you sure you want to log out from all devices? This will terminate all your active sessions.')) {
		return;
	}
	
	loading = true;
	error = '';
	
	try {
		const token = localStorage.getItem('admin_token');
		if (!token) {
			error = 'No active session';
			return;
		}
		
		const res = await fetch('/admin/api/session/logout-all', {
			method: 'POST',
			headers: { Authorization: `Bearer ${token}` }
		});
		
		if (res.ok) {
			// Redirect to login
			localStorage.removeItem('admin_token');
			localStorage.removeItem('session_id');
			window.location.href = '/admin/login';
		} else {
			const data = await res.json();
			error = data.error || 'Failed to logout all sessions';
		}
	} catch (e: any) {
		error = e.message || 'Failed to logout all sessions';
	} finally {
		loading = false;
	}
}

function formatDate(timestamp: number) {
	return new Date(timestamp).toLocaleString();
}

function formatDuration(timestamp: number) {
	const now = Date.now();
	const diff = now - timestamp;
	const minutes = Math.floor(diff / (1000 * 60));
	const hours = Math.floor(minutes / 60);
	const days = Math.floor(hours / 24);
	
	if (days > 0) return `${days} day${days > 1 ? 's' : ''}`;
	if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''}`;
	if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''}`;
	return 'Just now';
}
</script>

<div class="dashboard">
	<div class="dashboard-header">
		<h1>Admin Dashboard</h1>
		<p>Welcome to the CARRELink Administration Panel</p>
	</div>

	<div class="dashboard-grid">
		<div class="card">
			<h2>Quick Actions</h2>
			<div class="action-buttons">
				<a href="/admin/users" class="action-button">
					<span class="action-icon">👥</span>
					<span class="action-text">Manage Users</span>
				</a>
				<a href="/admin/acls" class="action-button">
					<span class="action-icon">🔐</span>
					<span class="action-text">Permission Management</span>
				</a>
			</div>
		</div>

		<div class="card">
			<h2>Session Information</h2>
			{#if loading}
				<div class="loading">Loading session info...</div>
			{:else if error}
				<div class="error">{error}</div>
				<button on:click={loadSessionInfo} class="retry-button">Retry</button>
			{:else if sessionInfo}
				<div class="session-info">
					<div class="session-item">
						<strong>Active Sessions:</strong> {sessionInfo.activeSessions} / {sessionInfo.maxSessions}
					</div>
					<div class="session-item">
						<strong>Current Session ID:</strong> 
						<span class="session-id">{sessionInfo.currentSession.sessionId.substring(0, 8)}...</span>
					</div>
					<div class="session-item">
						<strong>Created:</strong> {formatDate(sessionInfo.currentSession.createdAt)}
					</div>
					<div class="session-item">
						<strong>Last Activity:</strong> {formatDate(sessionInfo.currentSession.lastActivity)} ({formatDuration(sessionInfo.currentSession.lastActivity)} ago)
					</div>
					<div class="session-item">
						<strong>Expires:</strong> {formatDate(sessionInfo.currentSession.expiresAt)}
					</div>
					<div class="session-item">
						<strong>IP Address:</strong> {sessionInfo.currentSession.ip}
					</div>
					<div class="session-item">
						<strong>User Agent:</strong> 
						<span class="user-agent">{sessionInfo.currentSession.userAgent.substring(0, 50)}...</span>
					</div>
				</div>
				<div class="session-actions">
					<button on:click={logoutAllSessions} class="logout-all-button" disabled={loading}>
						{loading ? 'Processing...' : 'Logout All Sessions'}
					</button>
				</div>
			{:else}
				<div class="no-session">No session information available</div>
			{/if}
		</div>

		<div class="card">
			<h2>System Status</h2>
			<div class="status-grid">
				<div class="status-item">
					<span class="status-label">Authentication:</span>
					<span class="status-value status-ok">Active</span>
				</div>
				<div class="status-item">
					<span class="status-label">Session Management:</span>
					<span class="status-value status-ok">Enabled</span>
				</div>
				<div class="status-item">
					<span class="status-label">Security Headers:</span>
					<span class="status-value status-ok">Active</span>
				</div>
				<div class="status-item">
					<span class="status-label">HTTPS Enforcement:</span>
					<span class="status-value status-ok">Active</span>
				</div>
			</div>
		</div>
	</div>
</div>

<style>
.dashboard {
	display: flex;
	flex-direction: column;
	gap: 2rem;
}

.dashboard-header {
	text-align: center;
	margin-bottom: 1rem;
}

.dashboard-header h1 {
	font-size: 2.5rem;
	font-weight: 700;
	color: #3b82f6;
	margin-bottom: 0.5rem;
	letter-spacing: -0.5px;
}

.dashboard-header p {
	color: #9ca3af;
	font-size: 1.1rem;
	margin: 0;
}

.dashboard-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
	gap: 2rem;
}

.card {
	background: #2d2d2d;
	border-radius: 0.5rem;
	padding: 2rem;
	border: 1px solid #404040;
	box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
}

.card h2 {
	font-size: 1.5rem;
	font-weight: 600;
	color: #e5e7eb;
	margin-bottom: 1.5rem;
	border-bottom: 1px solid #404040;
	padding-bottom: 0.5rem;
}

.action-buttons {
	display: flex;
	flex-direction: column;
	gap: 1rem;
}

.action-button {
	display: flex;
	align-items: center;
	gap: 1rem;
	padding: 1rem;
	background: #404040;
	border: 1px solid #525252;
	border-radius: 0.4rem;
	color: #e5e7eb;
	text-decoration: none;
	transition: all 0.15s;
}

.action-button:hover {
	background: #525252;
	border-color: #3b82f6;
	transform: translateY(-2px);
	box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.action-icon {
	font-size: 1.5rem;
}

.action-text {
	font-weight: 600;
}

.session-info {
	display: flex;
	flex-direction: column;
	gap: 0.75rem;
	margin-bottom: 1.5rem;
}

.session-item {
	display: flex;
	justify-content: space-between;
	align-items: center;
	padding: 0.5rem 0;
	border-bottom: 1px solid #404040;
}

.session-item:last-child {
	border-bottom: none;
}

.session-item strong {
	color: #d1d5db;
	font-weight: 600;
}

.session-id {
	font-family: monospace;
	color: #3b82f6;
	background: #1a1a1a;
	padding: 0.2rem 0.4rem;
	border-radius: 0.2rem;
}

.user-agent {
	font-family: monospace;
	color: #9ca3af;
	font-size: 0.9rem;
}

.session-actions {
	display: flex;
	gap: 1rem;
}

.logout-all-button {
	background: #dc2626;
	color: white;
	border: none;
	border-radius: 0.4rem;
	padding: 0.75rem 1.5rem;
	font-weight: 600;
	cursor: pointer;
	transition: background 0.15s;
}

.logout-all-button:hover:not(:disabled) {
	background: #b91c1c;
}

.logout-all-button:disabled {
	opacity: 0.6;
	cursor: not-allowed;
}

.status-grid {
	display: flex;
	flex-direction: column;
	gap: 0.75rem;
}

.status-item {
	display: flex;
	justify-content: space-between;
	align-items: center;
	padding: 0.5rem 0;
}

.status-label {
	color: #d1d5db;
	font-weight: 500;
}

.status-value {
	font-weight: 600;
	padding: 0.25rem 0.75rem;
	border-radius: 0.25rem;
	font-size: 0.9rem;
}

.status-ok {
	background: #064e3b;
	color: #d1fae5;
}

.loading {
	color: #9ca3af;
	text-align: center;
	padding: 1rem;
}

.error {
	color: #fecaca;
	background: #7f1d1d;
	padding: 1rem;
	border-radius: 0.4rem;
	margin-bottom: 1rem;
	border: 1px solid #dc2626;
}

.retry-button {
	background: #3b82f6;
	color: white;
	border: none;
	border-radius: 0.4rem;
	padding: 0.5rem 1rem;
	cursor: pointer;
	transition: background 0.15s;
}

.retry-button:hover {
	background: #2563eb;
}

.no-session {
	color: #9ca3af;
	text-align: center;
	padding: 1rem;
	font-style: italic;
}
</style>
