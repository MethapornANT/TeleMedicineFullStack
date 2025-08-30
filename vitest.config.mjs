// vitest.config.mjs
export default {
    test: {
      environment: "node",
      globals: true,
      include: ["UnitTest.js"],
  
      coverage: {
        provider: "v8",
        reporter: ["text", "html"],
  
        // เปิด all เพื่อเก็บ coverage จากไฟล์ที่ “ต้องการ” แม้ไม่ได้ถูก import ตอนเทสต์
        all: true,
  
        // นับเฉพาะฝั่ง backend ที่เราต้องการวัด
        include: [
          "server.js",
          // ถ้าต่อไปแยกโค้ดเป็นไฟล์ย่อย ให้เพิ่มโฟลเดอร์ตรงนี้
          // "src/**/*.js",
          // "services/**/*.js",
          // "controllers/**/*.js"
        ],
  
        // ตัดไฟล์ที่ไม่อยากนับออกจากฐาน
        exclude: [
          "UnitTest.js",
          "vitest.config.mjs",
          "node_modules/**",
          "**/uploads/**",
          "**/config/**",          // ถ้ามีไฟล์ config แยก
          "**/telemed-web/**",     // ฝั่ง frontend ทั้งหมด
        ],
      },
    },
  };
  