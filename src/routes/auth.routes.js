
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const prisma = require("../lib/prisma");
const env = require("../config/env");
const { authRequired } = require("../middlewares/auth");

const router = express.Router();

// 1. REGISTER - Dang ky tai khoan
router.post("/register", async (req, res, next) => {
  try {
    const { username, fullname, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof fullname !== "string" ||
      typeof password !== "string" ||
      !username.trim() ||
      !fullname.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "username, fullname and password are required"
      });
    }

    const cleanUsername = username.trim();
    const cleanFullname = fullname.trim();

    // Kiem tra username da ton tai
    const existedUser = await prisma.user.findFirst({
      where: {
        username: cleanUsername
      }
    });

    if (existedUser) {
      return res.status(409).json({
        message: "Username already exists"
      });
    }

    // Tim role normal
    const normalRole = await prisma.role.findFirst({
      where: {
        rolename: "normal"
      }
    });

    // Tim membership co diem 10
    const normalMembership = await prisma.memberShip.findFirst({
      where: {
        score: 10
      }
    });

    if (!normalRole || !normalMembership) {
      return res.status(500).json({
        message: "Default role or membership not found"
      });
    }

    // Ma hoa mat khau
    const hashedPassword = await bcrypt.hash(password, 10);

    // Tao tai khoan
    const user = await prisma.user.create({
      data: {
        username: cleanUsername,
        fullname: cleanFullname,
        password: hashedPassword,
        roleid: normalRole.roleid,
        mid: normalMembership.mid
      },
      select: {
        uid: true,
        username: true,
        fullname: true,
        role: {
          select: {
            rolename: true
          }
        },
        membership: {
          select: {
            mname: true,
            score: true
          }
        }
      }
    });

    return res.status(201).json({
      message: "Register successfully",
      user
    });
  } catch (error) {
    next(error);
  }
});

// 2. LOGIN - Dang nhap
router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      !username.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "username and password are required"
      });
    }

    // Tim tai khoan
    const user = await prisma.user.findFirst({
      where: {
        username: username.trim()
      },
      include: {
        role: true,
        membership: true
      }
    });

    if (!user) {
      return res.status(401).json({
        message: "Invalid username or password"
      });
    }

    // Kiem tra mat khau
    const passwordMatched = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatched) {
      return res.status(401).json({
        message: "Invalid username or password"
      });
    }

    // Tao JWT token
    const token = jwt.sign(
      {
        uid: user.uid,
        username: user.username,
        role: user.role.rolename
      },
      env.JWT_SECRET,
      {
        expiresIn: env.JWT_EXPIRES_IN
      }
    );

    return res.status(200).json({
      token
    });
  } catch (error) {
    next(error);
  }
});

// 3. ME - Lay thong tin tai khoan
router.get("/me", authRequired, async (req, res, next) => {
  try {
    const user = await prisma.user.findUnique({
      where: {
        uid: req.user.uid
      },
      select: {
        uid: true,
        username: true,
        fullname: true,
        role: {
          select: {
            rolename: true
          }
        },
        membership: {
          select: {
            mname: true,
            score: true
          }
        }
      }
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    return res.status(200).json(user);
  } catch (error) {
    next(error);
  }
});

module.exports = router;
