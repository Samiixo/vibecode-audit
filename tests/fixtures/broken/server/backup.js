const { exec } = require("child_process");

function backup(dir) {
  // Команда собирается из переменной — в неё можно подставить что угодно.
  return exec(`tar czf ${dir}/backup.tgz ${dir}`);
}

module.exports = { backup };
