package com.gzu.javawebproject.controller;

import com.gzu.javawebproject.entity.Schedule;
import com.gzu.javawebproject.service.ScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/schedules")
public class ScheduleController {
    @Autowired
    private ScheduleService scheduleService;

    // 创建课程日程
    @PostMapping
    public String createSchedule(@RequestBody Schedule schedule) {
        scheduleService.createSchedule(schedule);
        return "Schedule created successfully!";
    }

    // 获取课程的日程
    @GetMapping("/{courseId}")
    public List<Schedule> getSchedulesByCourseId(@PathVariable Long courseId) {
        return scheduleService.getSchedulesByCourseId(courseId);
    }
}
