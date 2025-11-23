/* tutorcade-db — 初始化/补全表结构（MySQL 8.0） */
CREATE DATABASE IF NOT EXISTS `tutorcade-db` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `tutorcade-db`;

/* ---------- 用户 ---------- */
CREATE TABLE IF NOT EXISTS users (
  id               INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  username         VARCHAR(40) UNIQUE NOT NULL,
  pass_hash        CHAR(60)          NOT NULL,
  points           INT UNSIGNED      NOT NULL DEFAULT 0,
  created_at       TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  sec_question     VARCHAR(255)      NULL,
  sec_answer_hash  CHAR(60)          NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 如老表缺少新列，补列（忽略已存在错误）
ALTER TABLE users ADD COLUMN IF NOT EXISTS sec_question VARCHAR(255) NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sec_answer_hash CHAR(60) NULL;

/* ---------- 游戏目录 ---------- */
CREATE TABLE IF NOT EXISTS games (
  id        INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  title     VARCHAR(120) NOT NULL,
  category  VARCHAR(32)  NOT NULL,
  thumb     VARCHAR(128) NOT NULL,
  path      VARCHAR(128) NOT NULL,
  ready     TINYINT(1)   NOT NULL DEFAULT 1,
  `desc`    TEXT         NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 示例数据（仅当表为空时插入）
INSERT INTO games (title,category,thumb,path,ready,`desc`)
SELECT * FROM (
  SELECT 'APbioworld Biology Quest','Biology','img/apbio_cover.jpg','apbio_quest.html',1,'Dive into AP Biology concepts, master cell cycles, genetics & more.' UNION ALL
  SELECT 'SAT Reading Master','Reading','img/sat_reading_cover.jpg','sat_reader_adventure.html',1,'Practice critical‑reading passages and boost your SAT verbal score.' UNION ALL
  SELECT 'Math Puzzles','Math','img/math.jpg','math.html',1,'Solve arithmetic & algebra quests to level‑up your ninja skills.' UNION ALL
  SELECT 'Chronoquest','History','img/chronoquest.jpg','chronoquest.html',1,'Fix timeline anomalies by answering history trivia.' UNION ALL
  SELECT 'Chem Master','More','img/chem.jpg','chem_master.html',1,'Master chemical equations through interactive labs.' UNION ALL
  SELECT 'AP_Psychology','More','img/AP_psy.jpg','ap_psychology.html',1,'Learn AP Psychology by playing an engaging quest.'
) AS t
WHERE NOT EXISTS (SELECT 1 FROM games);

/* ---------- 会话 ---------- */
CREATE TABLE IF NOT EXISTS sessions (
  id          BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id     INT UNSIGNED NOT NULL,
  game_id     INT UNSIGNED NOT NULL,
  start_time  DATETIME     NOT NULL,
  end_time    DATETIME     NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (game_id) REFERENCES games(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

/* ---------- 每日任务 ---------- */
CREATE TABLE IF NOT EXISTS user_tasks (
  user_id    INT UNSIGNED NOT NULL,
  task_id    VARCHAR(20)  NOT NULL,
  task_date  DATE         NOT NULL,
  done       TINYINT(1)   NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id,task_id,task_date),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

/* ---------- 存档（可选） ---------- */
CREATE TABLE IF NOT EXISTS saves (
  id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id    INT UNSIGNED NOT NULL,
  name       VARCHAR(60)   NOT NULL,
  payload    MEDIUMTEXT    NOT NULL,
  created_at TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

/* ---------- UGC 社区（AI 生成游戏分享） ---------- */
CREATE TABLE IF NOT EXISTS ugc_games (
  id         BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
  user_id    INT UNSIGNED NOT NULL,
  title      VARCHAR(120)  NOT NULL,
  category   VARCHAR(32)   NOT NULL DEFAULT 'More',
  `desc`     VARCHAR(300)  NOT NULL DEFAULT '',
  html       MEDIUMTEXT    NOT NULL,
  likes      INT UNSIGNED  NOT NULL DEFAULT 0,
  published  TINYINT(1)    NOT NULL DEFAULT 1,
  created_at TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ugc_likes (
  user_id  INT UNSIGNED NOT NULL,
  game_id  BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (user_id, game_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (game_id) REFERENCES ugc_games(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
