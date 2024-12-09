package com.gzu.javawebproject.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.gzu.javawebproject.entity.Course;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CourseMapper extends BaseMapper<Course> {
    // 如果有复杂查询，比如按教师ID获取课程，可以添加额外方法
}
