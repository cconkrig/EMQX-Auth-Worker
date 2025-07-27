import fs from 'fs';
import path from 'path';

// Copy static assets from admin/static to public/admin
function copyAssets() {
    // Handle running from different directories
    const cwd = process.cwd();
    const isInAdminDir = cwd.endsWith('admin');
    
    const src = isInAdminDir ? 'static' : 'admin/static';
    const dest = isInAdminDir ? '../public/admin' : 'public/admin';
    
    if (!fs.existsSync(dest)) {
        fs.mkdirSync(dest, { recursive: true });
    }
    
    if (fs.existsSync(src)) {
        // Copy all files and directories recursively
        function copyRecursive(srcDir, destDir) {
            if (!fs.existsSync(destDir)) {
                fs.mkdirSync(destDir, { recursive: true });
            }
            
            fs.readdirSync(srcDir).forEach(file => {
                const srcPath = path.join(srcDir, file);
                const destPath = path.join(destDir, file);
                
                if (fs.statSync(srcPath).isDirectory()) {
                    copyRecursive(srcPath, destPath);
                } else {
                    fs.copyFileSync(srcPath, destPath);
                }
            });
        }
        
        copyRecursive(src, dest);
        console.log('✅ Static assets copied successfully');
    } else {
        console.log('⚠️  No static assets found in admin/static');
    }
}

copyAssets(); 