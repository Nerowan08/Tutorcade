/* tutorcade-db — 生产库初始化（MySQL 8.x）
   注意：
   1) 不包含 DROP DATABASE，避免生产误删。
   2) 如需变更库名，请同步修改 .env 中 DB_NAME 及应用连接。
*/

CREATE DATABASE IF NOT EXISTS `tutorcade-db`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `tutorcade-db`;

/* ---------- users ---------- */
CREATE TABLE IF NOT EXISTS users (
  id               INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  username         VARCHAR(40) UNIQUE NOT NULL,
  pass_hash        CHAR(60)          NOT NULL,
  points           INT UNSIGNED      NOT NULL DEFAULT 0,
  created_at       TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  /* 启用安全问题找回所需字段（允许为 NULL） */
  sec_question     VARCHAR(255) NULL,
  sec_answer_hash  CHAR(60)     NULL,
  UNIQUE KEY ux_users_username (username)
) ENGINE=InnoDB;

/* ---------- games ---------- */
CREATE TABLE IF NOT EXISTS games (
  id        INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  title     VARCHAR(120) NOT NULL,
  category  VARCHAR(32)  NOT NULL,
  thumb     VARCHAR(128) NOT NULL,
  path      VARCHAR(128) NOT NULL,
  ready     TINYINT(1)   NOT NULL DEFAULT 1,
  `desc`    TEXT         NOT NULL,
  KEY ix_games_category (category),
  KEY ix_games_ready (ready)
) ENGINE=InnoDB;

/* ---------- sessions（关键：支持“按日统计”和“今天范围查询”的索引”） ---------- */
CREATE TABLE IF NOT EXISTS sessions (
  id          BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id     INT UNSIGNED NOT NULL,
  game_id     INT UNSIGNED NOT NULL,
  start_time  DATETIME     NOT NULL,
  end_time    DATETIME     NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (game_id) REFERENCES games(id) ON DELETE CASCADE,
  KEY ix_sessions_user_start (user_id, start_time),
  KEY ix_sessions_user_end   (user_id, end_time)
) ENGINE=InnoDB;

/* ---------- user_tasks（用作“每日任务结算”的幂等锁） ---------- */
CREATE TABLE IF NOT EXISTS user_tasks (
  user_id    INT UNSIGNED NOT NULL,
  task_id    VARCHAR(20)  NOT NULL,
  task_date  DATE         NOT NULL,
  done       TINYINT(1)   NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, task_id, task_date),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  KEY ix_user_tasks_user_date (user_id, task_date)
) ENGINE=InnoDB;

/* ---------- saves（如后续使用存档） ---------- */
CREATE TABLE IF NOT EXISTS saves (
  id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id    INT UNSIGNED NOT NULL,
  name       VARCHAR(60)   NOT NULL,
  payload    MEDIUMTEXT    NOT NULL,
  created_at TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  KEY ix_saves_user (user_id),
  KEY ix_saves_created (created_at)
) ENGINE=InnoDB;

/* ---------- ai_games（社区共享的 AI 生成游戏） ---------- */
CREATE TABLE IF NOT EXISTS ai_games (
  id          BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id     INT UNSIGNED NULL,
  title       VARCHAR(160) NOT NULL,
  description VARCHAR(400) NULL,
  audience    VARCHAR(40)  NULL,
  path        VARCHAR(255) NOT NULL,
  public      TINYINT(1)   NOT NULL DEFAULT 1,
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  KEY ix_ai_games_public (public),
  KEY ix_ai_games_created (created_at)
) ENGINE=InnoDB;

/* ---------- 示例游戏数据（如已维护请删除本段） ---------- */
INSERT INTO games (title,category,thumb,path,ready,`desc`) VALUES
 ('APbioworld Biology Quest','Biology','img/apbio_cover.jpg','apbio_quest.html',1,'Dive into AP Biology concepts, master cell cycles, genetics & more.'),
 ('SAT Reading Master','Reading','img/sat_reading_cover.jpg','sat_reader_adventure.html',1,'Practice critical‑reading passages and boost your SAT verbal score.'),
 ('Math Puzzles','Math','img/math.jpg','math.html',1,'Solve arithmetic & algebra quests to level‑up your ninja skills.'),
 ('Chronoquest','History','img/chronoquest.jpg','chronoquest.html',1,'Fix timeline anomalies by answering history trivia.'),
 ('Chem Master','More','img/chem.jpg','chem_master.html',1,'Master chemical equations through interactive labs.'),
 ('AP_Psychology','More','img/AP_psy.jpg','ap_psychology.html',1,'Learn AP Psychology by playing an engaging quest.');
