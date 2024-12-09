package com.gzu.javawebproject.util;

import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

public class FileUploadUtil {
    private static final String UPLOAD_DIR = "/uploads"; // 设置你的文件保存路径

    // 保存文件到服务器
    public static String saveFile(MultipartFile file) throws IOException {
        String fileName = System.currentTimeMillis() + "_" + file.getOriginalFilename();
        File destination = new File(UPLOAD_DIR + "/" + fileName);
        file.transferTo(destination);
        return destination.getAbsolutePath();
    }
}
