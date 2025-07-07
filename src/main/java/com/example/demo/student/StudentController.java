package com.example.demo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1,"Rashmi"),
            new Student(2,"Dinuka"),
            new Student(2,"Dileka")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
      return STUDENTS.stream()
              .filter(student -> studentId.equals(student.getStudentId()))
              .findFirst()
              .orElseThrow(()->new IllegalArgumentException("Student "+studentId+" does not exist"));
    }
}
