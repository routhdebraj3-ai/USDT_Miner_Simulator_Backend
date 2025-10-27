// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { Schema } = mongoose;

// NOTE: business conversion (GH -> USDT) is done in controller or a config file.
// I'll reference a placeholder MINING_CONVERSION_FACTOR in comments.

const miningSessionSchema = new Schema({
  // Whether there is an active mining session (true while running)
  isActive: { type: Boolean, default: false },

  // When the session started and will end (ms since epoch)
  startTimeMs: { type: Number },
  endTimeMs: { type: Number },

  // Last time we updated "accumulatedGh" (ms since epoch).
  // Use this to "catch up" when app resumes.
  lastUpdatedMs: { type: Number },

  // Accumulated mined units (in GH units or whatever unit you pick) up to lastUpdatedMs
  accumulatedGh: { type: Number, default: 0 }, 

  // Current speed in GH per second for this session (varies with boosters).
  // Base speed is 30 (from your spec).
  speedGhPerSec: { type: Number, default: 30 },

  // How many extra milliseconds have been added by ad-based extensions
  extensionMs: { type: Number, default: 0 },

  // Session-scoped counters for ads watched:
  // - extAdsWatched: counts ads watched to extend time (max 2 in your flow)
  // - speedAdsWatched: counts ads watched to increase speed (max 2 => speed levels 0,1,2)
  extAdsWatched: { type: Number, default: 0 },
  speedAdsWatched: { type: Number, default: 0 },

  // Optional: history of session events for audit (ad watched, manual stop, etc.)
  events: [{
    type: { type: String }, // 'ad_extended', 'ad_speed', 'manual_stop', 'auto_stop'
    meta: { type: Schema.Types.Mixed }, // free-form: { adId, provider, extraMinutes }
    at: { type: Number, default: Date.now }
  }]
}, { _id: false });


const transactionSchema = new Schema({
  type: { type: String, enum: ['mine', 'convert', 'referral_reward', 'withdraw', 'purchase', 'surprise_gift', 'daily_bonus'], required: true },
  amountUsdt: { type: Number, default: 0 }, // Amount in USDT (for audit)
  amountCoins: { type: Number, default: 0 }, // optional
  note: { type: String },
  createdAt: { type: Date, default: Date.now }
}, { _id: false });


const userSchema = new Schema({
  googleId: { type: String, unique: true, sparse: true }, // sparse allows multiple nulls
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  photo: { type: String },
  password: { type: String }, // hashed password (optional for Google-only accounts)
  role: { type: String, enum: ['user', 'admin'], default: 'user' },

  location: {
    ip: { type: String },
    city: { type: String },
    region: { type: String },
    country: { type: String },
    latitude: { type: Number },
    longitude: { type: Number },
  },

  // Wallet balances (persisted on server)
  usdtBalance: { type: Number, default: 0 },      // usable USDT (converted or withdrawn)
  pendingUsdt: { type: Number, default: 0 },      // optional: if you want pending holds

  // "Coins" earned by referrals / daily bonus / chests (can be converted to USDT)
  coinsBalance: { type: Number, default: 0 },    // convertible coins
  totalCoinsEarned: { type: Number, default: 0 },

  // Referral info
  referralCode: { type: String, index: true },    // user's unique referral code
  referredBy: { type: Schema.Types.ObjectId, ref: 'User' },
  referralsCount: { type: Number, default: 0 },

  // Daily bonus / chest info
  lastDailyBonusAt: { type: Date },               // used to gate daily bonus
  dailyStreak: { type: Number, default: 0 },
  
  // Surprise gift info (NEW)
  lastSurpriseGiftAt: { type: Number }, // ms since epoch
  surpriseGiftClaims: { type: Number, default: 0 }, // total claims count

  // Active mining session (embedded)
  mining: { type: miningSessionSchema, default: () => ({}) },

  // Transaction / history log for conversions, mining finalizations, etc.
  transactions: { type: [transactionSchema], default: [] },

  // 🟢 CHANGED / NEW
  dailyBonus: {
    lastCycleStart: { type: Number, default: 0 },   // ms since epoch
    flipsOpened: { type: Number, default: 0 },      // used flips in this cycle
    totalFlipsClaimed: { type: Number, default: 0 } // optional analytics
  },

  // Ad history (simple counters & optionally a log)
  totalAdsWatched: { type: Number, default: 0 },

  // whether the Refer & Earn feature is enabled for the user
  referOn: { type: Boolean, default: true },

  // whether the Disclaimer screen (or acceptance gate) is enabled / shown for this user
  disclaimerOn: { type: Boolean, default: false },

  // whether the Rate Us screen (or acceptance gate) is enabled / shown for this user
  rateUsOn: { type: Boolean, default: true },

  // whether ads are enabled for this user (if you want to disable ads for a user)
  adsOn: { type: Boolean, default: true },

}, { timestamps: true });


// Password hashing
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Compare password
userSchema.methods.comparePassword = function (candidatePassword) {
  if (!this.password) return Promise.resolve(false);
  return bcrypt.compare(candidatePassword, this.password);
};

// Convert to JSON (hide password)
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};


/**
 * Compute and return the up-to-date mining info without modifying DB.
 * - nowMs: optional, pass Date.now()
 * - conversionFactorGhToUsdt: amount of USDT per 1 GH (server-side config)
 *
 * Returns: { accumulatedGh, accumulatedUsdt, remainingMs, isActive, speedGhPerSec }
 */
userSchema.methods.computeMiningSnapshot = function (nowMs = Date.now(), conversionFactorGhToUsdt = 0) {
  const mining = this.mining || {};
  if (!mining.isActive || !mining.startTimeMs) {
    return {
      isActive: false,
      accumulatedGh: mining.accumulatedGh || 0,
      accumulatedUsdt: (mining.accumulatedGh || 0) * conversionFactorGhToUsdt,
      remainingMs: 0,
      speedGhPerSec: mining.speedGhPerSec || 0,
      endTimeMs: mining.endTimeMs || null
    };
  }

  const lastUpdated = mining.lastUpdatedMs || mining.startTimeMs || nowMs;
  const effectiveEnd = Math.max(mining.endTimeMs || nowMs, lastUpdated); // safety
  const upToMs = Math.min(nowMs, effectiveEnd);

  const deltaMs = Math.max(0, upToMs - lastUpdated);
  const deltaSeconds = deltaMs / 1000.0;
  const deltaGh = (mining.speedGhPerSec || 0) * deltaSeconds;

  const accumulatedGh = (mining.accumulatedGh || 0) + deltaGh;
  const accumulatedUsdt = accumulatedGh * conversionFactorGhToUsdt;
  const remainingMs = Math.max(0, (mining.endTimeMs || nowMs) - nowMs);

  return {
    isActive: true,
    accumulatedGh,
    accumulatedUsdt,
    remainingMs,
    speedGhPerSec: mining.speedGhPerSec || 0,
    endTimeMs: mining.endTimeMs
  };
};


/**
 * Finalize mining session (compute final accumulation up to end time, store in usdtBalance or transactions).
 * This method updates the user instance in-memory; call save() afterwards or call the controller helper which uses atomic updates.
 *
 * - conversionFactorGhToUsdt: server config
 */
userSchema.methods.finalizeMiningSession = function (nowMs = Date.now(), conversionFactorGhToUsdt = 0) {
  if (!this.mining || !this.mining.isActive) return null;

  const snapshot = this.computeMiningSnapshot(nowMs, conversionFactorGhToUsdt);
  // Add the mined USDT to pending/available balance. Here we add to usdtBalance.
  const toAddUsdt = snapshot.accumulatedUsdt;

  // Reset mining session
  this.mining.isActive = false;
  this.mining.lastUpdatedMs = snapshot.endTimeMs || nowMs;
  this.mining.accumulatedGh = snapshot.accumulatedGh;
  this.mining.speedGhPerSec = this.mining.speedGhPerSec || 30;

  // credit user
  this.usdtBalance = (this.usdtBalance || 0) + toAddUsdt;
  this.transactions.push({
    type: 'mine',
    amountUsdt: toAddUsdt,
    note: 'Mining finalized and credited'
  });

  return { addedUsdt: toAddUsdt };
};


module.exports = mongoose.model('User', userSchema);
