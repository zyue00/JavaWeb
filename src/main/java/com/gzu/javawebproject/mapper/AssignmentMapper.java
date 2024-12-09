package com.gzu.javawebproject.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.gzu.javawebproject.entity.Assignment;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AssignmentMapper extends BaseMapper<Assignment> {
    // 自定义扩展：按课程ID查询作业
    // List<Assignment> findByCourseId(Long courseId);
}
