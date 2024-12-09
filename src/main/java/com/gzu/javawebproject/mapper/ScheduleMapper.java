package com.gzu.javawebproject.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.gzu.javawebproject.entity.Schedule;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface ScheduleMapper extends BaseMapper<Schedule> {
    // 示例：按课程ID查询日程
    // List<Schedule> findByCourseId(Long courseId);
}
