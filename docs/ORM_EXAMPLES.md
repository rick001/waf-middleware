# Parameterized queries (primary SQL injection defense)

This middleware only provides **heuristic signals**. **Always** use parameterized APIs so user input is never concatenated into SQL structure.

## Prisma

```typescript
// Safe: bound parameters
await prisma.user.findMany({ where: { email: userInput } });

// Unsafe: raw string interpolation — never do this
await prisma.$executeRawUnsafe(`SELECT * FROM users WHERE email = '${userInput}'`);

// Safer raw: tagged template or parameters
await prisma.$queryRaw`SELECT * FROM users WHERE email = ${userInput}`;
```

## TypeORM

```typescript
// Safe
await repo.createQueryBuilder('u').where('u.email = :email', { email: userInput }).getMany();

// Unsafe
await repo.query(`SELECT * FROM users WHERE email = '${userInput}'`);
```

## Knex

```typescript
knex('users').where({ email: userInput });
// or
knex('users').where('email', '=', userInput);
```

## node-pg (`pg`)

```typescript
await pool.query('SELECT * FROM users WHERE email = $1', [userInput]);
```

## mysql2

```typescript
await connection.execute('SELECT * FROM users WHERE email = ?', [userInput]);
```

## Sequelize

```typescript
await User.findAll({ where: { email: userInput } });
```

References: [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
