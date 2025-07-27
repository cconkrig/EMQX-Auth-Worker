import fs from 'fs';
import path from 'path';

// Copy static assets from admin/static to public/admin
function copyAssets() {
    const src = 'admin/static';
    const dest = 'public/admin';
    
    if (!fs.existsSync(dest)) {
        fs.mkdirSync(dest, { recursive: true });
    }
    
    if (fs.existsSync(src)) {
        fs.readdirSync(src).forEach(file => {
            const srcPath = path.join(src, file);
            const destPath = path.join(dest, file);
            
            if (fs.statSync(srcPath).isDirectory()) {
                if (!fs.existsSync(destPath)) {
                    fs.mkdirSync(destPath, { recursive: true });
                }
                fs.readdirSync(srcPath).forEach(subFile => {
                    fs.copyFileSync(path.join(srcPath, subFile), path.join(destPath, subFile));
                });
            } else {
                fs.copyFileSync(srcPath, destPath);
            }
        });
        console.log('✅ Static assets copied successfully');
    } else {
        console.log('⚠️  No static assets found in admin/static');
    }
}

copyAssets(); 