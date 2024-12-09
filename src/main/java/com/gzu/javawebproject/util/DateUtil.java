package com.gzu.javawebproject.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

public class DateUtil {
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // 格式化日期为字符串
    public static String format(LocalDateTime dateTime) {
        return dateTime.format(FORMATTER);
    }

    // 从字符串解析日期
    public static LocalDateTime parse(String dateTimeString) {
        return LocalDateTime.parse(dateTimeString, FORMATTER);
    }

    // 检查是否过期
    public static boolean isExpired(LocalDateTime dateTime) {
        return LocalDateTime.now().isAfter(dateTime);
    }

    // 计算两个时间的差值 (单位: 天)
    public static long daysBetween(LocalDateTime start, LocalDateTime end) {
        return ChronoUnit.DAYS.between(start, end);
    }
}
