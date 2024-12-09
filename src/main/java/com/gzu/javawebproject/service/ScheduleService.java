package com.gzu.javawebproject.service;

import com.gzu.javawebproject.entity.Schedule;
import java.util.List;

public interface ScheduleService {
    Schedule createSchedule(Schedule schedule);
    List<Schedule> getSchedulesByCourseId(Long courseId);
    void deleteSchedule(Long id);
}
