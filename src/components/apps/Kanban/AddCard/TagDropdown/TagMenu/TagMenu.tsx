import React, { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Col, Popconfirm, Row } from 'antd';
import { DeleteOutlined } from '@ant-design/icons';
import { Tag } from 'components/apps/Kanban/interfaces';
import { AddTag } from './AddTag/AddTag';
import { kanbanTags } from 'constants/kanbanTags';
import { Btn } from '../../AddCard.styles';
import * as S from './TagMenu.styles';

const initialTags = Object.values(kanbanTags);

interface TagMenuProps {
  selectedTags: Tag[];
  setSelectedTags: (func: (state: Tag[]) => Tag[]) => void;
}

export const TagMenu: React.FC<TagMenuProps> = ({ selectedTags, setSelectedTags }) => {
  const [isMain, setMain] = useState(true);
  const [tags, setTags] = useState<Tag[]>(initialTags);

  const { t } = useTranslation();

  const selectTag = useCallback(
    (tag) => {
      setSelectedTags((prev) =>
        prev.includes(tag) ? prev.filter((selectedTag) => selectedTag.title !== tag.title) : [...prev, tag],
      );
    },
    [setSelectedTags, selectedTags],
  );

  const removeTag = useCallback(
    (tag) => {
      setTags(tags.filter((stateTag) => stateTag.title !== tag.title));
    },
    [setTags, tags],
  );

  const tagsElements = useMemo(
    () =>
      tags.map((tag, index) => (
        <Col span={24} key={index}>
          <S.Tag
            as={Row}
            justify="space-between"
            align="middle"
            gutter={[5, 5]}
            color={tag.bgcolor}
            isActive={selectedTags.includes(tag)}
            onClick={() => selectTag(tag)}
          >
            <Col>{tag.title}</Col>
            <Col>
              <Popconfirm title={t('common.deleteQuestion')} onConfirm={() => removeTag(tag)}>
                <DeleteOutlined />
              </Popconfirm>
            </Col>
          </S.Tag>
        </Col>
      )),
    [tags, selectTag, selectedTags, removeTag],
  );

  return (
    <S.TagMenu>
      {isMain ? (
        <>
          <Row gutter={[20, 20]}>
            <Col span={24}>
              <Row gutter={[10, 10]}>{tagsElements}</Row>
            </Col>
            <Col span={24}>
              <Btn onClick={() => setMain(false)}>{t('kanban.addTags')}</Btn>
            </Col>
          </Row>
        </>
      ) : (
        <AddTag setMain={setMain} setTags={setTags} />
      )}
    </S.TagMenu>
  );
};