const {Router} = require('express')
const bcrypt = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()


// /api/auth/register
router.post(
  '/register',
  [
    check('email', 'Uncorrect email').isEmail(),
    check('password', 'Min length of password is 6 symbols')
      .isLength({ min: 6 })
  ],
  async (req, res) => {
  try {
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Uncorrect way of registration'
      })
    }

    const {email, password} = req.body

    const candidate = await User.findOne({ email })

    if (candidate) {
      return res.status(400).json({ message: 'It seems that user already exists' })
    }

    const hashedPassword = await bcrypt.hash(password, 12)
    const user = new User({ email, password: hashedPassword })

    await user.save()

    res.status(201).json({ message: 'User was created ' })

  } catch (e) {
    res.status(500).json({ message: 'Server error, highly recomend to contact support team' })
  }
})

// /api/auth/login
router.post(
  '/login',
  [
    check('email', 'Write down correct email').normalizeEmail().isEmail(),
    check('password', 'Dont forget about your password ').exists()
  ],
  async (req, res) => {
  try {
    const errors = validationResult(req)

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Uncorrect way of sign in'
      })
    }

    const {email, password} = req.body

    const user = await User.findOne({ email })

    if (!user) {
      return res.status(400).json({ message: 'User was not found' })
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if (!isMatch) {
      return res.status(400).json({ message: 'Uncorrect password,try one more time' })
    }

    const token = jwt.sign(
      { userId: user.id },
      config.get('jwtSecret'),
      { expiresIn: '1h' }
    )

    res.json({ token, userId: user.id })

  } catch (e) {
    res.status(500).json({ message: 'If something doesnt work its only  fault of backend developer with name Edward Podvoiskyi' })
  }
})


module.exports = router
