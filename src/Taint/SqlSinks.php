<?php

namespace Weirdan\DoctrinePsalmPlugin\Taint;

use Psalm\Internal\Provider\ClassLikeStorageProvider;
use Psalm\Plugin\EventHandler\AfterCodebasePopulatedInterface;
use Psalm\Plugin\EventHandler\Event\AfterCodebasePopulatedEvent;
use Psalm\Storage\ClassLikeStorage;
use Psalm\Type\TaintKind;

use function array_keys;
use function in_array;
use function is_int;
use function strtolower;

/**
 * Makes the SQL and DQL arguments of the DBAL connection, the entity manager and both query builders SQL sinks.
 *
 * Done on the scanned methods rather than in the stubs: a stub replaces the whole signature, and the
 * signatures of these methods differ between the DBAL and ORM versions a project may install.
 * A sink applies to the class named here and to every class that overrides the method.
 */
final class SqlSinks implements AfterCodebasePopulatedInterface
{
    private const QUERY = [0];

    private const CONDITION_OF_JOIN = [3];

    private const ORDER = [0, 1];

    /** @var array<class-string, array<string, list<int>>> the positions of the SQL arguments, by method */
    private const SINKS = [
        'Doctrine\DBAL\Connection' => [
            'executeQuery' => self::QUERY,
            'executeCacheQuery' => self::QUERY,
            'executeStatement' => self::QUERY,
            'executeUpdate' => self::QUERY,
            'prepare' => self::QUERY,
            'fetchAssociative' => self::QUERY,
            'fetchNumeric' => self::QUERY,
            'fetchOne' => self::QUERY,
            'fetchAllNumeric' => self::QUERY,
            'fetchAllAssociative' => self::QUERY,
            'fetchAllKeyValue' => self::QUERY,
            'fetchAllAssociativeIndexed' => self::QUERY,
            'fetchFirstColumn' => self::QUERY,
            'iterateNumeric' => self::QUERY,
            'iterateAssociative' => self::QUERY,
            'iterateKeyValue' => self::QUERY,
            'iterateAssociativeIndexed' => self::QUERY,
            'iterateColumn' => self::QUERY,
        ],
        'Doctrine\ORM\EntityManagerInterface' => [
            'createQuery' => self::QUERY,
            'createNativeQuery' => self::QUERY,
        ],
        'Doctrine\ORM\Query' => ['setDQL' => self::QUERY],
        'Doctrine\ORM\QueryBuilder' => [
            'select' => self::QUERY,
            'addSelect' => self::QUERY,
            'where' => self::QUERY,
            'andWhere' => self::QUERY,
            'orWhere' => self::QUERY,
            'having' => self::QUERY,
            'andHaving' => self::QUERY,
            'orHaving' => self::QUERY,
            'groupBy' => self::QUERY,
            'addGroupBy' => self::QUERY,
            'orderBy' => self::ORDER,
            'addOrderBy' => self::ORDER,
            'join' => self::CONDITION_OF_JOIN,
            'innerJoin' => self::CONDITION_OF_JOIN,
            'leftJoin' => self::CONDITION_OF_JOIN,
        ],
        'Doctrine\DBAL\Query\QueryBuilder' => [
            'select' => self::QUERY,
            'addSelect' => self::QUERY,
            'where' => self::QUERY,
            'andWhere' => self::QUERY,
            'orWhere' => self::QUERY,
            'having' => self::QUERY,
            'andHaving' => self::QUERY,
            'orHaving' => self::QUERY,
            'groupBy' => self::QUERY,
            'addGroupBy' => self::QUERY,
            'orderBy' => self::ORDER,
            'addOrderBy' => self::ORDER,
            'join' => self::CONDITION_OF_JOIN,
            'innerJoin' => self::CONDITION_OF_JOIN,
            'leftJoin' => self::CONDITION_OF_JOIN,
            'rightJoin' => self::CONDITION_OF_JOIN,
        ],
    ];

    public static function afterCodebasePopulated(AfterCodebasePopulatedEvent $event): void
    {
        foreach (ClassLikeStorageProvider::getAll() as $storage) {
            $lineage = self::lineage($storage);

            foreach (self::SINKS as $class => $methods) {
                if (! in_array(strtolower($class), $lineage, true)) {
                    continue;
                }

                foreach ($methods as $method => $positions) {
                    $methodStorage = $storage->methods[strtolower($method)] ?? null;
                    if ($methodStorage === null) {
                        continue;
                    }

                    foreach ($positions as $position) {
                        if (! isset($methodStorage->params[$position])) {
                            continue;
                        }

                        $param = $methodStorage->params[$position];
                        /** @psalm-suppress DocblockTypeContradiction, RedundantConditionGivenDocblockType Psalm 6 lists the taints by name, Psalm 7 in a bitmap */
                        if (is_int($param->sinks)) {
                            $param->sinks |= TaintKind::INPUT_SQL;
                        } else {
                            $param->sinks = [...($param->sinks ?? []), TaintKind::INPUT_SQL];
                        }
                    }
                }
            }
        }
    }

    /** @return list<string> the class, its parents and its interfaces, in lower case */
    private static function lineage(ClassLikeStorage $storage): array
    {
        return [
            strtolower($storage->name),
            ...array_keys($storage->parent_classes),
            ...array_keys($storage->class_implements),
            ...array_keys($storage->parent_interfaces),
        ];
    }
}
