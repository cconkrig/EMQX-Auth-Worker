<script lang="ts">
import { onMount } from 'svelte';

let message = 'Hello World';
let mounted = false;

onMount(() => {
	console.log('Main page mounted');
	mounted = true;
});
</script>

<div style="background: #23283a; color: white; padding: 20px; min-height: 100vh;">
	<h1>EMQX Admin Dashboard</h1>
	<p>Message: {message}</p>
	<p>Mounted: {mounted}</p>
	<p>Time: {new Date().toLocaleString()}</p>
	
	<div style="background: green; color: white; padding: 10px; margin: 10px;">
		DEBUG: Main page is rendering - Mounted: {mounted}
	</div>
	
	<a href="/admin/login" style="color: #60a5fa;">Go to Login</a>
</div>
