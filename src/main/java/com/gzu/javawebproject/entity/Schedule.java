package com.gzu.javawebproject.entity;

import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDate;

@Data
@TableName("schedule")
public class Schedule {
    @TableId
    private Long id;
    private Long courseId;
    private LocalDate date;
    private String startTime;
    private String endTime;
    private String location;
}
