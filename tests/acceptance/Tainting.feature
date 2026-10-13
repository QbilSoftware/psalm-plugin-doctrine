Feature: Tainting
  In order to prevent SQL injection when using Doctrine
  As a Psalm user
  I need Psalm to spot taint sources and sinks

  Background:
    Given I have Doctrine plugin enabled
    And I have the following code preamble
      """
      <?php
      use Doctrine\DBAL\Connection;

      /**
       * @psalm-suppress InvalidReturnType
       * @return Connection
       */
      function connection() {}

      """
    # Psalm enables cache when there's a composer.lock file
    And I have empty composer.lock

  @Connection::prepare
  @Connection::exec
  @Connection::query
  @Connection::executeUpdate
  @Connection::executeStatement
  Scenario Outline: Using user input on Connection's query methods
    Given I have the following code
      """
      $sql = 'INSERT INTO sometable (item_name) VALUES ("'.$_GET['untrusted'].'")';
      connection()-><method>($sql);
      """
    When I run Psalm with taint analysis
    Then I see these errors
      | Type                       | Message                       |
      | /TaintedInput\|TaintedSql/ | /Detected tainted (sql\|SQL)/ |
    And I see no other errors
  Examples:
    | method           |
    | prepare          |
    | exec             |
    | query            |
    | executeUpdate    |
    | executeStatement |

  @Connection::quote
  Scenario: Using Connection's quote method on user input
    Given I have the following code
      """
      $sql = 'SELECT * FROM sometable WHERE id=' . connection()->quote($_GET['untrusted']);
      connection()->query($sql);
      """
    When I run Psalm with taint analysis
    Then I see no errors

  @Connection::executeQuery
  @Connection::fetchOne
  Scenario Outline: Using user input on Connection's query and fetch methods
    Given I have the following code
      """
      $sql = 'SELECT name FROM sometable WHERE item_name = "'.$_GET['untrusted'].'"';
      connection()-><method>($sql);
      """
    When I run Psalm with taint analysis
    Then I see these errors
      | Type                       | Message                       |
      | /TaintedInput\|TaintedSql/ | /Detected tainted (sql\|SQL)/ |
    And I see no other errors
  Examples:
    | method                     |
    | executeQuery               |
    | fetchOne                   |
    | fetchAssociative           |
    | fetchNumeric               |
    | fetchAllAssociative        |
    | fetchAllNumeric            |
    | fetchAllKeyValue           |
    | fetchAllAssociativeIndexed |
    | fetchFirstColumn           |
    | iterateAssociative         |
    | iterateNumeric             |
    | iterateColumn              |

  @Connection::fetchOne
  Scenario: Using user input as a parameter of Connection's fetch methods
    Given I have the following code
      """
      connection()->fetchOne('SELECT name FROM sometable WHERE item_name = ?', [$_GET['untrusted']]);
      """
    When I run Psalm with taint analysis
    Then I see no errors

  @EntityManagerInterface::createQuery
  Scenario Outline: Using user input in DQL or native SQL
    Given I have the following code
      """
      /**
       * @psalm-suppress InvalidReturnType
       * @return Doctrine\ORM\EntityManagerInterface
       */
      function entityManager() {}

      entityManager()-><method>('SELECT u FROM User u WHERE u.name = "'.$_GET['untrusted'].'"'<arguments>);
      """
    When I run Psalm with taint analysis
    Then I see these errors
      | Type                       | Message                       |
      | /TaintedInput\|TaintedSql/ | /Detected tainted (sql\|SQL)/ |
    And I see no other errors
  Examples:
    | method            | arguments                                     |
    | createQuery       |                                               |
    | createNativeQuery | , new Doctrine\ORM\Query\ResultSetMapping()   |

  @QueryBuilder::andWhere
  Scenario Outline: Using user input in the query builders
    Given I have the following code
      """
      /**
       * @psalm-suppress InvalidReturnType
       * @return <builder>
       */
      function builder() {}

      builder()-><method>(<arguments>);
      """
    When I run Psalm with taint analysis
    Then I see these errors
      | Type                       | Message                       |
      | /TaintedInput\|TaintedSql/ | /Detected tainted (sql\|SQL)/ |
    And I see no other errors
  Examples:
    | builder                          | method    | arguments                                          |
    | Doctrine\ORM\QueryBuilder        | andWhere  | 'u.name = "'.$_GET['untrusted'].'"'                |
    | Doctrine\ORM\QueryBuilder        | orderBy   | 'u.name', $_GET['untrusted']                       |
    | Doctrine\ORM\QueryBuilder        | leftJoin  | 'u.group', 'g', 'WITH', $_GET['untrusted']         |
    | Doctrine\DBAL\Query\QueryBuilder | where     | 'name = "'.$_GET['untrusted'].'"'                  |
    | Doctrine\DBAL\Query\QueryBuilder | addOrderBy | $_GET['untrusted']                                |
