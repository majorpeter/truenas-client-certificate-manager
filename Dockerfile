FROM node:16

WORKDIR /usr/src/app
COPY package*.json ./

RUN npm install

COPY *.ts tsconfig.json ./
RUN npm run-script build
COPY dist/config.json ./dist

CMD ["npm", "start"]
