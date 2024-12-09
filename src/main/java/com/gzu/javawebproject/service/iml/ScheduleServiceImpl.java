package com.gzu.javawebproject.service.iml;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.gzu.javawebproject.entity.Schedule;
import com.gzu.javawebproject.mapper.ScheduleMapper;
import com.gzu.javawebproject.service.ScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ScheduleServiceImpl implements ScheduleService {
    @Autowired
    private ScheduleMapper scheduleMapper;

    @Override
    public Schedule createSchedule(Schedule schedule) {
        scheduleMapper.insert(schedule);
        return schedule;
    }

    @Override
    public List<Schedule> getSchedulesByCourseId(Long courseId) {
        return scheduleMapper.selectList(new QueryWrapper<Schedule>().eq("course_id", courseId));
    }

    @Override
    public void deleteSchedule(Long id) {
        scheduleMapper.deleteById(id);
    }
}
